#!/system/bin/sh

MODDIR=${0%/*}

if [ -x "$MODDIR/vintf_keymint.sh" ]; then
  "$MODDIR/vintf_keymint.sh" "$MODDIR"
fi
