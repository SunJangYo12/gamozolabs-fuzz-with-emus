set term wxt persist size 600,500
set xlabel "Fuzz Cases"
set ylabel "Coverage"
set logscale x
set multiplot layout 2,1
set datafile separator ","
set grid mxtics, xtics, ytics, mytics
set key left

set title "Coverage"
plot "stats.txt" u 2:3 w l t "+cov",\
     "stats_nocc.txt" u 2:3 w l t "-cov"

set title "Crashes"
set ylabel "Crashes"
plot "stats.txt" u 2:4 w l axes x1y2 t "+cov",\
     "stats_nocc.txt" u 2:4 w l axes x1y2 t "-cov"
