// Original educational buffer chain; not a characterized manufacturing cell.
module timing(input a, output y);
wire n;
BUF b0 (.A(a), .Y(n));
BUF b1 (.A(n), .Y(y));
endmodule
