#set output "graph-scalability.png"
set output "graph-scalability-size.png"
set terminal png size 900,400
set datafile sep ','
#set xlabel "# Variables"
set xlabel "# Conjunction"
set ylabel "Time (ms)"
#set xrange [0:205]
#set yrange [0:50]

set xrange [0:33]
set yrange [0:10]

set style line 1 lc rgb '#0060ad' lt 1 lw 2 pt 7 ps 1.5

#plot "performance_test.csv" using 1:($2*1000)  with linespoints ls 1 notitle
plot "performance_test_size.csv" using 1:($2*1000)  with linespoints ls 1 notitle
