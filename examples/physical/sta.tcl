# Run with: sta -exit sta.tcl; OpenTapeout captures stdout directly.
# Both referenced files and this script must be pinned in policy v2.
puts "OT_BEGIN opensta $env(OPENTAPEOUT_RUN_ID)"
read_liberty timing.lib
read_verilog timing.v
link_design timing
read_sdc timing.sdc
set_cmd_units -time ns
puts "OT_TIME_UNIT ns"
puts "OT_CLOCKS [llength [all_clocks]]"
puts "OT_CONSTRAINTS_OK [check_setup -verbose]"
puts "OT_SECTION SETUP_PATHS"
report_checks -path_delay max -digits 12
puts "OT_SECTION_END SETUP_PATHS"
puts "OT_SECTION HOLD_PATHS"
report_checks -path_delay min -digits 12
puts "OT_SECTION_END HOLD_PATHS"
puts "OT_SECTION SETUP_WORST"
report_worst_slack -max -digits 12
puts "OT_SECTION_END SETUP_WORST"
puts "OT_SECTION HOLD_WORST"
report_worst_slack -min -digits 12
puts "OT_SECTION_END HOLD_WORST"
puts "OT_SECTION SETUP_TNS"
report_tns -max -digits 12
puts "OT_SECTION_END SETUP_TNS"
puts "OT_SECTION HOLD_TNS"
report_tns -min -digits 12
puts "OT_SECTION_END HOLD_TNS"
puts "OT_END opensta $env(OPENTAPEOUT_RUN_ID)"
