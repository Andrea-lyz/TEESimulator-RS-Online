MODDIR=${0%/*}
cd $MODDIR

# Fork-based supervisor for instant restart
./supervisor ./daemon "$MODDIR" &

# Clear logd size persist properties once boot completes
(
  until [ "$(getprop sys.boot_completed)" = "1" ]; do
    sleep 1
  done
  setprop persist.logd.size ""
  setprop persist.logd.size.crash ""
  setprop persist.logd.size.system ""
  setprop persist.logd.size.main ""
) &
