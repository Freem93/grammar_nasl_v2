#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(45433);
 script_version ("$Revision: 1.2 $");
 script_cvs_date("$Date: 2011/03/21 15:27:34 $");

 script_name(english: "Memory Information (via DMI)");
 script_summary(english: "Extract memory information from dmidecode");
 
 script_set_attribute(attribute:"synopsis", value:
"Information about the remote system's memory devices can be read." );
 script_set_attribute(attribute:"description", value:
"Using the SMBIOS (aka DMI) interface, it was possible to retrieve
information about the remote system's memory devices, such as the
total amount of installed memory." );
 script_set_attribute(attribute:"solution", value:"n/a" );
 script_set_attribute(attribute:"risk_factor", value:"None" );

 script_set_attribute(attribute:"plugin_publication_date", value: "2010/04/06");
 script_set_attribute(attribute:"plugin_type", value:"local");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2010-2011 Tenable Network Security, Inc.");
 script_family(english: "General");
 script_dependencies("bios_get_info_ssh.nasl");
 script_require_keys("Host/dmidecode");
 exit(0);
}


buf = get_kb_item("Host/dmidecode");
if (isnull(buf)) exit(1, "The 'Host/dmidecode' KB setting is missing.");
if ("Memory Device" >!< buf) exit(0, "No DMI memory device information.");

values = make_list();
found = 0;

lines = split(buf, keep: 0);
drop_flag = 1;

total_sz = 0;
foreach l (lines)
{
  if (ereg(string: l, pattern: '^Memory Device'))
  {
   drop_flag = 0;
   continue;
  }
  else if (ereg(string: l, pattern: '^[A-Z]')) drop_flag = 1; 
  if (drop_flag) continue;
  pat = strcat('^[ \t]+Size[ \t]*:[  \t]*([0-9]+)[ \t]+(MB|GB)');
  v = eregmatch(string: l, pattern: pat);
  if (! isnull(v))
  {
    sz = int(v[1]);
    if (v[2] == 'GB') sz *= 1024;
    total_sz += sz;
    found ++;
  }
} 

if (! found) exit(1, "Empty DMI memory module information.");

security_note(port: 0, extra: 
  strcat('\nTotal memory : ', total_sz, ' MB'));
