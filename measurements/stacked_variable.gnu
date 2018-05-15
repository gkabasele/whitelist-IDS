set output "multi_var.png"
set terminal png size 1000,600

set tmargin 0
set bmargin 3

set style line 1 lc rgb '#0060ad' lt 1 lw 2 pt 7 ps 1.5
set style line 2 lc rgb '#dd181f' lt 1 lw 2 pt 5 ps 1.5
set style line 3 lc rgb '#f48942' lt 1 lw 2 pt 6 ps 1.5
set style line 4 lc rgb '#7142f4' lt 1 lw 2 pt 8 ps 1.5
set style line 5 lc rgb '#42adf4' lt 1 lw 2 pt 9 ps 1.5
set style line 6 lc rgb '#2f9954' lt 1 lw 2 pt 4 ps 1.5

set multiplot layout 3, 1 title "Variable evolution\n" font ",12"

#Plot Tank1
set datafile separator ","
set yrange[0:120]
set xrange[0:30]
set ylabel "Value"
unset xtics

plot "attack.csv" using 1:15 title "Tank1-Attack" with linespoints ls 2, \
     "state.csv" using 1:15 title "Tank1-Normal" with linespoints ls 1

#Plot WagonCar
set datafile separator ","
set yrange[0:100]
set xrange[0:30]
set ylabel "Value"
unset xtics
plot "state.csv" using 1:21 title "WagonCar-Normal" with linespoints ls 3, \
     "attack.csv" using 1:21 title "WagonCar-Attack" with linespoints ls 4

#Plot Silo1
set datafile separator ","
set yrange[0:140]
set xrange[0:30]
set ylabel "Value"
set xlabel "Time(s)"
set xtics nomirror
plot "state.csv" using 1:4 title "SiloA-Normal" with linespoints ls 5, \
     "attack.csv" using 1:4 title "SiloA-Attack" with linespoints ls 6
unset multiplot


