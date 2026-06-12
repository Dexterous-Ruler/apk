/*
 * APKSHIELD — Frida runtime instrumentation for live dynamic analysis.
 *
 * The self-hosted "detonate it in a sandbox" path. Run the suspect APK on a
 * rooted emulator/device with frida-server, attach this script, and it logs
 * the malicious runtime behavior as it happens: SMS interception/sending,
 * network egress (the real C2), crypto (string/payload decryption), runtime
 * dex loading (the second-stage payload), accessibility abuse, and reflection.
 *
 * Usage:
 *   # on the analysis VM (NEVER your daily phone):
 *   frida -U -f <package> -l tools/frida_hooks.js --no-pause
 *   # or attach:  frida -U <package> -l tools/frida_hooks.js
 *
 * Output is JSON lines on stdout; pipe to a file to feed back into the report.
 * SAFETY: only run inside an isolated, throwaway emulator/VM.
 */
'use strict';

function emit(kind, data) {
  send(JSON.stringify({ t: kind, ts: Date.now(), data: data }));
}

Java.perform(function () {
  // ---- SMS interception / sending (OTP theft) ----
  try {
    var SmsManager = Java.use('android.telephony.SmsManager');
    SmsManager.sendTextMessage.overload(
      'java.lang.String', 'java.lang.String', 'java.lang.String',
      'android.app.PendingIntent', 'android.app.PendingIntent'
    ).implementation = function (dest, sc, text, a, b) {
      emit('SMS_SEND', { to: dest, body: text });
      return this.sendTextMessage(dest, sc, text, a, b);
    };
  } catch (e) {}

  try {
    var SmsMessage = Java.use('android.telephony.SmsMessage');
    SmsMessage.getMessageBody.implementation = function () {
      var body = this.getMessageBody();
      emit('SMS_READ', { body: body });
      return body;
    };
  } catch (e) {}

  // ---- network egress (the real C2 endpoints) ----
  try {
    var URL = Java.use('java.net.URL');
    URL.openConnection.overload().implementation = function () {
      emit('NET_CONNECT', { url: this.toString() });
      return this.openConnection();
    };
  } catch (e) {}
  try {
    var HttpURLConnection = Java.use('java.net.HttpURLConnection');
    HttpURLConnection.connect.implementation = function () {
      emit('HTTP', { url: this.getURL().toString(), method: this.getRequestMethod() });
      return this.connect();
    };
  } catch (e) {}

  // ---- crypto (payload / string decryption) ----
  try {
    var Cipher = Java.use('javax.crypto.Cipher');
    Cipher.doFinal.overload('[B').implementation = function (input) {
      var out = this.doFinal(input);
      try {
        emit('CRYPTO', { algo: this.getAlgorithm(),
          out_preview: Java.use('java.lang.String').$new(out).toString().slice(0, 120) });
      } catch (e2) { emit('CRYPTO', { algo: this.getAlgorithm() }); }
      return out;
    };
  } catch (e) {}

  // ---- runtime dex loading (the second-stage payload) ----
  ['dalvik.system.DexClassLoader', 'dalvik.system.PathClassLoader',
   'dalvik.system.InMemoryDexClassLoader'].forEach(function (cl) {
    try {
      var Loader = Java.use(cl);
      Loader.$init.overload('java.lang.String', 'java.lang.String',
        'java.lang.String', 'java.lang.ClassLoader').implementation =
        function (a, b, c, d) {
          emit('DEX_LOAD', { loader: cl, path: a });
          return this.$init(a, b, c, d);
        };
    } catch (e) {}
  });

  // ---- reflection (hidden API resolution) ----
  try {
    var Method = Java.use('java.lang.reflect.Method');
    Method.invoke.implementation = function (obj, args) {
      emit('REFLECT', { method: this.getName(),
        cls: this.getDeclaringClass().getName() });
      return this.invoke(obj, args);
    };
  } catch (e) {}

  // ---- shell command execution ----
  try {
    var Runtime = Java.use('java.lang.Runtime');
    Runtime.exec.overload('java.lang.String').implementation = function (cmd) {
      emit('SHELL', { cmd: cmd });
      return this.exec(cmd);
    };
  } catch (e) {}

  // ---- accessibility abuse (overlay / auto-click) ----
  try {
    var ANI = Java.use('android.view.accessibility.AccessibilityNodeInfo');
    ANI.performAction.overload('int').implementation = function (a) {
      emit('A11Y_ACTION', { action: a });
      return this.performAction(a);
    };
  } catch (e) {}

  emit('READY', { msg: 'APKSHIELD frida hooks installed' });
});
