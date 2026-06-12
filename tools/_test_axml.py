"""Build a tiny manifest and confirm androguard parses it."""
import sys, io, zipfile
sys.path.insert(0, r"C:\Users\tanis\hackathon\apk\tools")
from axml import Element, build_axml

root = Element("manifest", [
    (False, "package", "com.kyc.sbi.rewards", "str"),
    (True, "versionCode", 7, "int"),
    (True, "versionName", "1.0", "str"),
])
root.add(Element("uses-permission", [(True, "name", "android.permission.SEND_SMS", "str")]))
root.add(Element("uses-permission", [(True, "name", "android.permission.RECEIVE_SMS", "str")]))
root.add(Element("uses-permission", [(True, "name", "android.permission.BIND_ACCESSIBILITY_SERVICE", "str")]))
app = root.add(Element("application", [(True, "label", "SBl YONO Rewards", "str")]))
act = app.add(Element("activity", [(True, "name", ".MainActivity"), ] if False else [(True, "name", ".MainActivity", "str"), (True, "exported", True, "bool")]))
intent = act.add(Element("intent-filter"))
intent.add(Element("action", [(True, "name", "android.intent.action.MAIN", "str")]))
intent.add(Element("category", [(True, "name", "android.intent.category.LAUNCHER", "str")]))

axml = build_axml(root)
print("axml bytes:", len(axml))

from androguard.core.axml import AXMLPrinter
ap = AXMLPrinter(axml)
xml = ap.get_xml().decode("utf-8")
print(xml)

# now wrap in a minimal zip and parse with APK to test get_permissions
buf = io.BytesIO()
with zipfile.ZipFile(buf, "w", zipfile.ZIP_STORED) as z:
    z.writestr("AndroidManifest.xml", axml)
buf.seek(0)
from androguard.core.apk import APK
a = APK(buf.read(), raw=True)
print("package:", a.get_package())
print("app_name:", a.get_app_name())
print("permissions:", a.get_permissions())
print("activities:", a.get_activities())
