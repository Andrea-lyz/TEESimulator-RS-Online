#!/system/bin/sh

MODDIR=${1:-${0%/*}}
API_LEVEL=${2:-$(getprop ro.build.version.sdk 2>/dev/null)}
OUT_DIR="$MODDIR/system/etc/vintf/manifest"
OUT_FILE="$OUT_DIR/teesimulator-keymint.xml"

keymint_aidl_version_for_api() {
  case "$1" in
    31|32) echo 1 ;;
    33) echo 2 ;;
    34|35) echo 3 ;;
    36|37|38|39) echo 4 ;;
    *)
      if [ "$1" -ge 40 ] 2>/dev/null; then
        echo 4
      else
        echo ""
      fi
      ;;
  esac
}

AIDL_VERSION=$(keymint_aidl_version_for_api "$API_LEVEL")

if [ -z "$AIDL_VERSION" ]; then
  rm -f "$OUT_FILE" "$OUT_FILE.tmp" 2>/dev/null
  exit 0
fi

umask 022
mkdir -p "$OUT_DIR" || exit 1

TMP_FILE="$OUT_FILE.$$"
cat > "$TMP_FILE" <<EOF
<manifest version="1.0" type="device">
    <hal format="aidl">
        <name>android.hardware.security.keymint</name>
        <version>$AIDL_VERSION</version>
        <interface>
            <name>IKeyMintDevice</name>
            <instance>default</instance>
        </interface>
    </hal>
</manifest>
EOF

chmod 0644 "$TMP_FILE"
mv -f "$TMP_FILE" "$OUT_FILE"
