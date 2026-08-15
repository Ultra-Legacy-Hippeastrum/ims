//SPDX-License-Identifier: GPL-2.0
package me.phh.sip

import android.telephony.Rlog
import android.telephony.TelephonyManager
import android.util.Base64

data class SipAkaResult(val res: ByteArray, val ck: ByteArray, val ik: ByteArray)

sealed class SipAkaChallengeResult {
    data class Success(val akaResult: SipAkaResult) : SipAkaChallengeResult()
    data class SynchronizationFailure(val auts: ByteArray) : SipAkaChallengeResult()
}

private const val TAG = "PHH SipChallenge"

private fun quoteDigestOpaque(opaque: String?): String {
    if (opaque == null) return ""
    val escaped = opaque.replace("\\", "\\\\").replace("\"", "\\\"")
    return ",opaque=\"$escaped\""
}

fun sipAkaChallenge(tm: TelephonyManager, nonceB64: String): SipAkaResult {
    return when (val result = sipAkaChallengeForRegistration(tm, nonceB64)) {
        is SipAkaChallengeResult.Success -> result.akaResult
        is SipAkaChallengeResult.SynchronizationFailure -> {
            throw Exception(
                "AKA Challenge from SIP returned synchronization failure " +
                    "AUTS length=${result.auts.size}",
            )
        }
    }
}

fun getUsimAid(tm: TelephonyManager): String {
    try {
        val method = tm.javaClass.methods.firstOrNull {
            it.name == "getAidForAppType" && it.parameterTypes.size == 1
        }
        if (method != null) {
            val aid = method.invoke(tm, TelephonyManager.APPTYPE_USIM) as? String
            if (!aid.isNullOrBlank()) {
                Rlog.d(TAG, "TelephonyManager.getAidForAppType returned AID: $aid")
                return aid
            }
        }
    } catch (_: Throwable) {}

    Rlog.w(TAG, "getAidForAppType failed, using a0000000871002 as fallback")
    return "a0000000871002"
}

fun sipAkaChallengeForRegistration(
    tm: TelephonyManager,
    nonceB64: String,
): SipAkaChallengeResult {
    val nonce = Base64.decode(nonceB64, Base64.DEFAULT)
    val rand = nonce.take(16).toByteArray()
    val autn = nonce.drop(16).take(16).toByteArray()

    val challengeBytes = listOf(rand.size.toByte()) + rand.toList() + listOf(autn.size.toByte()) + autn.toList()
    val challengeArray = challengeBytes.toByteArray()
    val payloadHex = challengeArray.joinToString("") { "%02x".format(it) }

    Rlog.d(TAG, "Requesting USIM AKA authentication via APDU challengeBytes=${challengeArray.size}")

    val usimAid = getUsimAid(tm)

    val iccChannel = tm.iccOpenLogicalChannel(usimAid)
        ?: throw Exception("Failed to open logical channel to USIM (returned null)")
    val channel = iccChannel.channel
    if (channel <= 0) {
        throw Exception("Failed to open logical channel to USIM: channelId=$channel")
    }

    var apduResponseHex: String?
    try {
        apduResponseHex = tm.iccTransmitApduLogicalChannel(
            channel,
            0x00,               // cla
            0x88,               // ins (AUTHENTICATE)
            0x00,               // p1
            0x81,               // p2 (3G Security Context)
            challengeArray.size,// p3 (Lc = 34)
            payloadHex          // data
        )

        if (!apduResponseHex.isNullOrEmpty() && apduResponseHex.length >= 4) {
            val sw1 = apduResponseHex.substring(apduResponseHex.length - 4, apduResponseHex.length - 2).toInt(16)
            val sw2 = apduResponseHex.substring(apduResponseHex.length - 2).toInt(16)

            if (sw1 == 0x61) {
                apduResponseHex = tm.iccTransmitApduLogicalChannel(
                    channel, 0x00, 0xC0, 0x00, 0x00, sw2, ""
                )
            }
        }
    } finally {
        tm.iccCloseLogicalChannel(channel)
    }

    if (apduResponseHex.isNullOrEmpty()) {
        throw Exception("AKA Challenge APDU returned empty response")
    }

    val rawResponseBytes = apduResponseHex.chunked(2)
        .map { it.toInt(16).toByte() }
        .toByteArray()

    if (rawResponseBytes.size < 2) {
        throw Exception("AKA Challenge APDU response too short")
    }

    val response = rawResponseBytes.copyOfRange(0, rawResponseBytes.size - 2)

    val responseTag = response[0].toInt() and 0xff
    if (responseTag != 0xdb) {
        if (responseTag == 0xdc) {
            val autsLen = response[1].toInt() and 0xff
            val auts = response.copyOfRange(2, 2 + autsLen)
            return SipAkaChallengeResult.SynchronizationFailure(auts)
        }
        throw Exception("AKA Challenge failed with tag=0x${responseTag.toString(16)}")
    }

    val responseStream = response.iterator()
    responseStream.nextByte() // 0xdb
    val resLen = responseStream.nextByte().toInt() and 0xff
    val res = (0 until resLen).map { responseStream.nextByte() }.toList()
    val ckLen = responseStream.nextByte().toInt() and 0xff
    val ck = (0 until ckLen).map { responseStream.nextByte() }.toList()
    val ikLen = responseStream.nextByte().toInt() and 0xff
    val ik = (0 until ikLen).map { responseStream.nextByte() }.toList()

    Rlog.d(TAG, "USIM AKA authentication succeeded resLen=$resLen ckLen=$ckLen ikLen=$ikLen")
    return SipAkaChallengeResult.Success(
        SipAkaResult(res = res.toByteArray(), ck = ck.toByteArray(), ik = ik.toByteArray())
    )
}

data class SipAkaDigestSess(
    val user: String,
    val realm: String,
    val uri: String,
    val nonceB64: String,
    val opaque: String?,
    private val akaResult: SipAkaResult
) {
    var nonceCount: String = "0"
    var cnonce: String = ""
    private val H1 = ("$user:$realm:".toByteArray() + akaResult.res).toMD5()
    private val H2 = "REGISTER:$uri".toMD5()
    var digest: String = ""

    init {
        Rlog.d(TAG, "Prepared session AKA digest inputs")
        increment()
    }

    fun increment() {
        nonceCount = "%08d".format(nonceCount.toInt() + 1)
        cnonce = randomBytes(8).toHex() // 16 bytes on some traces
        digest = "$H1:$nonceB64:$nonceCount:$cnonce:auth:$H2".toMD5()
        Rlog.d(TAG, "Computed session AKA digest nc=$nonceCount")
    }

    override fun toString(): String =
        """Digest username="$user",realm="$realm",nonce="$nonceB64",uri="$uri",response="$digest",algorithm=AKAv1-MD5,cnonce="$cnonce",qop=auth,nc=$nonceCount""" +
            quoteDigestOpaque(opaque)
}

data class SipAkaSynchronizationDigestSess(
    val user: String,
    val realm: String,
    val uri: String,
    val nonceB64: String,
    val opaque: String?,
    private val auts: ByteArray,
) {
    var nonceCount: String = "0"
    var cnonce: String = ""
    private val autsB64 = Base64.encodeToString(auts, Base64.NO_WRAP)
    private val H1 = "$user:$realm:".toMD5()
    private val H2 = "REGISTER:$uri".toMD5()
    var digest: String = ""

    init {
        Rlog.d(TAG, "Prepared session AKA synchronization digest inputs")
        increment()
    }

    fun increment() {
        nonceCount = "%08d".format(nonceCount.toInt() + 1)
        cnonce = randomBytes(8).toHex()
        // RFC 3310 section 3.4: when auts is present, calculate the
        // credentials using an empty password instead of RES.
        digest = "$H1:$nonceB64:$nonceCount:$cnonce:auth:$H2".toMD5()
        Rlog.d(TAG, "Computed session AKA synchronization digest nc=$nonceCount")
    }

    override fun toString(): String =
        "Digest username=\"$user\",realm=\"$realm\",nonce=\"$nonceB64\",uri=\"$uri\"," +
                "response=\"$digest\",algorithm=AKAv1-MD5,cnonce=\"$cnonce\",qop=auth,nc=$nonceCount" +
                quoteDigestOpaque(opaque) +
                ",auts=\"$autsB64\""
}


data class SipAkaDigest(
    val user: String,
    val realm: String,
    val uri: String,
    val nonceB64: String,
    val opaque: String?,
    private val akaResult: SipAkaResult
) {
    private val H1 = ("$user:$realm:".toByteArray() + akaResult.res).toMD5()
    private val H2 = "REGISTER:$uri".toMD5()
    var digest: String = ""

    init {
        Rlog.d(TAG, "Prepared non-session AKA digest inputs")
        increment()
    }

    fun increment() {
        digest = "$H1:$nonceB64:$H2".toMD5()
        Rlog.d(TAG, "Computed non-session AKA digest")
    }

    override fun toString(): String =
        """Digest username="$user",realm="$realm",nonce="$nonceB64",uri="$uri",response="$digest",algorithm=AKAv1-MD5""" +
            quoteDigestOpaque(opaque)
}

data class SipAkaSynchronizationDigest(
    val user: String,
    val realm: String,
    val uri: String,
    val nonceB64: String,
    val opaque: String?,
    private val auts: ByteArray,
) {
    private val autsB64 = Base64.encodeToString(auts, Base64.NO_WRAP)
    private val H1 = "$user:$realm:".toMD5()
    private val H2 = "REGISTER:$uri".toMD5()
    var digest: String = ""

    init {
        Rlog.d(TAG, "Prepared non-session AKA synchronization digest inputs")
        increment()
    }

    fun increment() {
        // RFC 3310 section 3.4: when auts is present, calculate the
        // credentials using an empty password instead of RES.
        digest = "$H1:$nonceB64:$H2".toMD5()
        Rlog.d(TAG, "Computed non-session AKA synchronization digest")
    }

    override fun toString(): String =
        "Digest username=\"$user\",realm=\"$realm\",nonce=\"$nonceB64\",uri=\"$uri\"," +
                "response=\"$digest\",algorithm=AKAv1-MD5" +
                quoteDigestOpaque(opaque) +
                ",auts=\"$autsB64\""
}
