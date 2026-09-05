# Original educational geometry. NOT a foundry PDK or manufacturing design.
layout = RBA::Layout.new
layout.dbu = 0.001
cell = layout.create_cell("RESISTOR")
r = layout.layer(1, 0)
c = layout.layer(2, 0)
labels = layout.layer(2, 1)
cell.shapes(r).insert(RBA::Box.new(1000, 0, 11000, 2000))
cell.shapes(c).insert(RBA::Box.new(-1000, 0, 1000, 2000))
cell.shapes(c).insert(RBA::Box.new(11000, 0, 13000, 2000))
cell.shapes(labels).insert(RBA::Text.new("A", RBA::Trans.new(0, 1000)))
cell.shapes(labels).insert(RBA::Text.new("B", RBA::Trans.new(12000, 1000)))
if $defect == "width"
  cell.shapes(r).insert(RBA::Box.new(20000, 0, 20100, 2000))
end
layout.write("resistor.gds")
