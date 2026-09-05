# An explicit virtual clock and both min/max IO constraints.
create_clock -name virtual -period 10
set_input_delay -clock virtual -max 1 [get_ports a]
set_input_delay -clock virtual -min 0.1 [get_ports a]
set_output_delay -clock virtual -max 1 [get_ports y]
set_output_delay -clock virtual -min -0.1 [get_ports y]
set_input_transition 0.1 [get_ports a]
set_load 0.01 [get_ports y]
