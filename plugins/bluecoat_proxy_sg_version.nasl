#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(68992);
 script_version("$Revision: 1.2 $");
 script_cvs_date("$Date: 2013/10/04 20:18:18 $");

 script_name(english:"Blue Coat ProxySG SGOS Version");
 script_summary(english:"Obtains the SGOS version of the remote Blue Coat ProxySG Device");

 script_set_attribute(attribute:"synopsis", value:
"It is possible to obtain the SGOS version number of the remote ProxySG
Blue Coat device.");
 script_set_attribute(attribute:"description", value:
"The remote host is running SGOS, an operating system for Blue Coat
ProxySG devices.

It is possible to read the ProxySG SGOS version number by connecting to
the device via SSH.");
 script_set_attribute(attribute:"solution", value:"n/a");
 script_set_attribute(attribute:"risk_factor", value:"None");

 script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/22");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/o:bluecoat:sgos");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2013 Tenable Network Security, Inc.");
 script_family(english:"Firewalls");

 script_dependencies("ssh_get_info.nasl");
 script_require_ports("Host/BlueCoat/ProxySG/show_version");
 exit(0);
}

include("audit.inc");
include("misc_func.inc");

showver = get_kb_item_or_exit("Host/BlueCoat/ProxySG/show_version");

patterns = make_array(
  "Version:",       "^Version: (.*)$",
  "Release id:",    "^Release id: (.*)$",
  "UI Version:",    "^UI Version: (([0-9]+\.[0-9]+[^ ]+) Build: ([0-9]+))",
  "Serial number:", "^Serial number: (.*)$"
);

lines = split(showver);
foreach line (lines)
{
  foreach kp (keys(patterns))
  {
    if (kp >!< line) continue;
    matches = eregmatch(pattern:patterns[kp], string:line);
    if (isnull(matches)) continue;

    if (kp == "Version:")
      set_kb_item(name:"Host/BlueCoat/ProxySG/vendor_version_string", value: chomp(matches[1]));
    else if (kp == "Release id:")
      set_kb_item(name:"Host/BlueCoat/ProxySG/release_id", value: chomp(matches[1]));
    else if (kp == "Serial number:")
      set_kb_item(name:"Host/BlueCoat/ProxySG/serial_number", value: chomp(matches[1]));
    else if (kp == "UI Version:")
    {
      ui_ver = str_replace(string:chomp(matches[1]), find:":", replace:"");
      ver = chomp(matches[2]);
      build = chomp(matches[3]);

      # Create version-check friendly version
      # e.g.: a.b.c.build-number
      # Pad with zeroes if needed
      granularity = max_index(split(ver, sep:".", keep:FALSE));
      if (granularity < 4)
        for (i=granularity; i<4; i++)
          ver += ".0";

      ver = ver + "." + build;

      set_kb_item(name:"Host/BlueCoat/ProxySG/Version", value: ver);
      set_kb_item(name:"Host/BlueCoat/ProxySG/UI_Version", value: ui_ver);
      set_kb_item(name:"Host/BlueCoat/ProxySG/Confidence", value:100);
    }
  }
}
