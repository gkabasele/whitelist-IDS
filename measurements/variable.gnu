set output "graph-variable.png"
set terminal png size 900,400
set datafile sep ','
set xlabel "Time"
set ylabel "Value"
set xrange [0:30]
set yrange [0:120]
set style line 1 lc rgb '#0060ad' lt 1 lw 2 pt 7 ps 1.5
set style line 2 lc rgb '#dd181f' lt 1 lw 2 pt 5 ps 1.5
set style line 3 lc rgb '#f48942' lt 1 lw 2 pt 6 ps 1.5
set style line 4 lc rgb '#7142f4' lt 1 lw 2 pt 8 ps 1.5
set style line 5 lc rgb '#42adf4' lt 1 lw 2 pt 9 ps 1.5
set style line 6 lc rgb '#2f9954' lt 1 lw 2 pt 4 ps 1.5


plot "state.csv" using 1:15 title "Tank1-Normal" with linespoints ls 1, \
     "attack.csv" using 1:15 title "Tank1-Attack" with linespoints ls 2, \
     "state.csv" using 1:21 title "WagonCar-Normal" with linespoints ls 3, \
     "attack.csv" using 1:21 title "WagonCar-Attack" with linespoints ls 4, \
     "state.csv" using 1:4 title "SiloA-Normal" with linespoints ls 5, \
     "attack.csv" using 1:4 title "SiloA-Attack" with linespoints ls 6
