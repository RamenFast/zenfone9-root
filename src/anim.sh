#!/system/bin/sh
# anim.sh — keep the display awake and the GPU actively rendering. The exploit's work only takes
# effect while the GPU is genuinely rendering. NOTE: pace the swipes. A tight `input swipe` loop
# spawns an input process continuously and destabilises the system (observed reboots); one swipe
# every ~400 ms is plenty to keep the UI compositor busy.
while true; do
    input swipe 540 1500 540 700 120
    sleep 0.4
done
