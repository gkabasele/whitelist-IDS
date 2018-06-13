#set output "graph-distance-critical2.png"
#set terminal png size 900,400
#set datafile sep ','
#set xlabel "Time"
#set ylabel "Distance"
#set xrange [0:30]
#set yrange [0:0.5]
set style line 1 lc rgb '#0060ad' lt 1 lw 2 pt 7 ps 1.5
set style line 2 lc rgb '#dd181f' lt 1 lw 2 pt 5 ps 1.5
#
#plot "attack2_critical.csv" using 1:24 title "Attack" with linespoints ls 2, \
#     "state2_critical.csv" using 1:24 title "Normal" with linespoints ls 1

set output "graph-distance-normal2.png"
set terminal png size 1000, 400
set datafile sep ','
set xlabel "Time"
set ylabel "Distance"
set xrange [0:110]
set yrange [0:0.05]

plot "attack2_normal.csv" using 1:24 title "Attack" with linespoints ls 2, \
     "state2_normal.csv" using 1:24 title "Normal" with linespoints ls 1

