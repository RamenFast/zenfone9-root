#!/system/bin/sh
# anim.sh — keep the display awake and the GPU actively rendering. The exploit's drawstate rides the
# GPU's active rendering: with the screen off or the GPU idle, our submitted work does not take effect
# (measured: 0/4 writes landed at a dark lockscreen vs 3/4 with the screen awake and touches animating).
while true; do
    input swipe 540 1600 540 600 120
done
