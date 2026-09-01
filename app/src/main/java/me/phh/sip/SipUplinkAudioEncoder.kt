//SPDX-License-Identifier: GPL-2.0
package me.phh.sip

import android.media.MediaCodec
import android.telephony.Rlog

data class SipUplinkEncoderDrainState(
    val firstPacket: Boolean,
    val realFrameCount: Int,
)

object SipUplinkAudioEncoder {
    fun queuePcmInput(
        logTag: String,
        encoder: MediaCodec,
        buffer: ByteArray,
        size: Int,
        gainQ8: Int,
        logInput: Boolean,
    ) {
        if (logInput) {
            val allZero = buffer.take(size.coerceAtLeast(0)).all { it == 0.toByte() }
            Rlog.d(logTag, "AudioRecord.read nRead=$size allZero=$allZero (bufferSize=${buffer.size})")
        }

        if (size > 0) {
            SipUplinkGain.applyInPlace(
                buffer = buffer,
                size = size,
                gainQ8 = gainQ8,
            )
        }

        // AudioRecord.read() can return more PCM than a single MediaCodec
        // input buffer holds (one input buffer is sized for one encoder
        // frame period, e.g. 20ms of AMR-WB @16kHz = 640 bytes, but a read
        // can return a full internal buffer's worth, e.g. 1280 bytes for
        // two frame periods). Feeding all of `size` into one input buffer
        // in a single put() can throw BufferOverflowException if it
        // doesn't fit. Split into as many input buffers as needed instead,
        // each holding at most that buffer's real remaining() capacity.
        //
        // size<=0 still submits exactly one (empty) buffer, matching the
        // original behavior.
        var offset = 0
        do {
            val inBufIdx = encoder.dequeueInputBuffer(-1)
            val inBuf = encoder.getInputBuffer(inBufIdx)!!
            inBuf.clear()

            val chunkSize = (size - offset).coerceIn(0, inBuf.remaining())
            inBuf.put(buffer, offset, chunkSize)

            // Fake timestamp but it is not appearing in the output stream anyway
            encoder.queueInputBuffer(inBufIdx, 0, chunkSize, System.nanoTime() / 1000, 0)

            offset += chunkSize
        } while (offset < size)
    }

    fun drainEncodedOutput(
        logTag: String,
        encoder: MediaCodec,
        audioCodec: NegotiatedAudioCodec,
        firstPacket: Boolean,
        realFrameCount: Int,
        nextSequenceNumber: () -> Int,
        nextTimestamp: () -> Int,
        sendFrame: (
            sequenceNumber: Int,
            timestamp: Int,
            storageFrame: ByteArray,
            marker: Boolean,
            frameType: Int,
            frameSize: Int,
            realFrameCount: Int,
        ) -> Boolean,
    ): SipUplinkEncoderDrainState {
        var currentFirstPacket = firstPacket
        var currentRealFrameCount = realFrameCount

        // Drain all output frames the encoder produced for this input.
        // Use -1 (block) on the first call so we always wait for the async
        // C2 encoder to finish; use 0 on subsequent calls to collect any
        // additional frames without stalling.  Without draining, the output
        // queue fills up and dequeueInputBuffer(-1) deadlocks.
        val outBufInfo = MediaCodec.BufferInfo()
        var drainTimeout = -1L
        var outCount = 0
        while (true) {
            val outBufIdx = encoder.dequeueOutputBuffer(outBufInfo, drainTimeout)
            drainTimeout = 0L
            if (outBufIdx == MediaCodec.INFO_OUTPUT_FORMAT_CHANGED) {
                Rlog.d(logTag, "Encoder output format changed")
                continue
            }
            if (outBufIdx < 0) {
                break
            }
            outCount++

            val outBuf = encoder.getOutputBuffer(outBufIdx)!!

            val encoderData = ByteArray(outBufInfo.size)
            outBuf.get(encoderData)
            encoder.releaseOutputBuffer(outBufIdx, false)

            if (currentRealFrameCount == 0) {
                Rlog.d(logTag, "First encoder output: size=${outBufInfo.size}")
            }

            var bufPos = 0
            while (bufPos < outBufInfo.size) {
                val ft = (encoderData[bufPos].toUByte().toInt() shr 3) and 0xf
                val frameSize = SipAmrRtpPayload.storageFrameSizeBytes(audioCodec, ft)
                if (frameSize == null) {
                    Rlog.w(logTag, "Skipping encoder frame with unsupported AMR FT=$ft codec=${audioCodec.name}")
                    break
                }
                if (outBufInfo.size - bufPos < frameSize) break

                val sequenceNumber = nextSequenceNumber()
                val timestamp = nextTimestamp()
                val storageFrame = encoderData.copyOfRange(bufPos, bufPos + frameSize)
                if (!sendFrame(
                    sequenceNumber,
                    timestamp,
                    storageFrame,
                    currentFirstPacket,
                    ft,
                    frameSize,
                    currentRealFrameCount,
                )) break

                currentFirstPacket = false
                currentRealFrameCount++
                bufPos += frameSize
            }
        }

        return SipUplinkEncoderDrainState(
            firstPacket = currentFirstPacket,
            realFrameCount = currentRealFrameCount,
        )
    }
}
