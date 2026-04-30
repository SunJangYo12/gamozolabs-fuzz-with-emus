set term wxt persist size 800,500
set title "Fuzzer Stats"
set xlabel "Fuzz Cases"
set ylabel "Count"
set logscale x
set datafile separator ","
set grid mxtics, xtics, ytics, mytics
plot "stats.txt" u 2:3 w l t "Coverage",\
     "stats.txt" u 2:4 w l axes x1y2 t "Crashes"
