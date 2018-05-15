set output "graph-coil.png"
set terminal png size 1000,600

set tmargin 0
set bmargin 3

set style line 1 lc rgb '#0060ad' lt 1 lw 2 pt 7 ps 1.5
set style line 2 lc rgb '#dd181f' lt 1 lw 2 pt 5 ps 1.5
set style line 3 lc rgb '#f48942' lt 1 lw 2 pt 6 ps 1.5
set style line 4 lc rgb '#7142f4' lt 1 lw 2 pt 8 ps 1.5
set style line 5 lc rgb '#42adf4' lt 1 lw 2 pt 9 ps 1.5
set style line 6 lc rgb '#2f9954' lt 1 lw 2 pt 4 ps 1.5

set multiplot layout 3, 1 title "Coil evolution\n" font ",12"


#Plot WagonEnd
set datafile sep ","
set ylabel "Value"
set xrange [0:30]
set yrange [0:4]
unset xtics

plot "attack.csv" using 1:14 title "WagonEnd-Attack" with linespoints ls 2, \
     "state.csv" using 1:14 title "WagonEnd-Normal" with linespoints ls 1

#Plot ValveCharcoal
set datafile sep ","
set ylabel "Value"
set xrange [0:30]
set yrange [0:4]
unset xtics

plot "attack.csv" using 1:16 title "ValveChar-Attack" with linespoints ls 3, \
     "state.csv" using 1:16 title "ValveChar-Normal" with linespoints ls 4
 
#Plot Boths 
set datafile sep ","
set ylabel "Value"
set xlabel "Time(s)"
set xrange [0:30]
set yrange [0:6]
set xtics nomirror

plot "attack.csv" using 1:($14+$16) title "WE-VC-Attack" with linespoints ls 5, \
     "state.csv" using 1:($14+$16) title "WE-VC-Normal" with linespoints ls 6
unset multiplot
