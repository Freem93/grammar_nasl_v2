#TRUSTED 7dbaa37d1c25df0ec187c6d1eed3e0b4140194d8b140d9f1f239c08ca29c953f8103fa25e3f83ed90c0323d9c17448ce2aa4daec90224b16b92822e52f99dd1bd1bdb5e47d522e7c98e8ef4c8dc1d86789d00de8ecbd70b5043233cdfc57beb0178646c13ec815a87fc90464bf8cfcf7ab9cc4065f0d1dd13614c1222bc44f29a4ece611757a96e5227f5d0d4b9d7ceef2a7ba50114527e9d61d3670d81cd8d9327d00e9b073fa4f2b0d2fd5f6b21ffa4eb9b6d64513ef06bd5181435871a1ef65043b4c56b385e75822b7e45d981b20c506aed21eb42e5144b3422e4e330329bf4bd0e14bd1e2a0ba34929699edfab83077b5cdb247338c86a49eb11f038459572e100ab2780fafeb400f814961748dd0dac0e35a56d8fe9bca5e65e45707054dfc8f911f2dbfcfa30b7d3b6f8bc8ba8cdcd9d7ddf6c0aa0e26f5a5289de5eef44d4698f0c4b85dfcb6a821836d287d1199e5d3b5abef1a4d57f73993e4617f513fa0fb8da4e1e1684760a44ffa8b6722f78a87cf58d0ca4149c883769cdea7973edba7501815a68f8d043c088eca083d7c11b6b91ff32929cf54e4bd53b04a2c207b9d52045ba2373ef0bb313e47362a0647fd0461ea5b918255ce92e01704b4a726aa2f08c7cc936f83a25754e351dd46f410e5064658a063d9c5e73369605a238e3487f7a683d4fab84e27bd16eff3ddf7f8fd2695f50befe6af42ca9eed
#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(34098);
 script_version ("1.10");
 script_set_attribute(attribute:"plugin_modification_date", value: "2015/06/02");

 script_name(english: "BIOS version (SSH)");
 script_summary(english: "Run dmidecode");
 
 script_set_attribute(attribute:"synopsis", value:
"The BIOS version could be read." );
 script_set_attribute(attribute:"description", value:
"Using the SMBIOS (aka DMI) interface, it was possible to get the BIOS
vendor and version." );
 script_set_attribute(attribute:"solution", value:"N/A");
 script_set_attribute(attribute:"risk_factor", value:
"None" );
 script_set_attribute(attribute:"plugin_publication_date", value: "2008/09/08");
 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"agent", value:"unix");
 script_end_attributes();

 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2008-2015 Tenable Network Security, Inc.");
 script_family(english: "General");

 script_dependencies("ssh_settings.nasl", "ssh_get_info.nasl");
 script_require_ports("Services/ssh", 22, "nessus/product/agent");
 script_exclude_keys("BIOS/Vendor", "BIOS/Version", "BIOS/ReleaseDate");
 exit(0);
}
include("ssh_func.inc");
include("telnet_func.inc");
include("hostlevel_funcs.inc");

if (get_kb_item("BIOS/Vendor") && get_kb_item("BIOS/Version") && get_kb_item("BIOS/ReleaseDate")) exit(0);

# We may support other protocols here
if ( islocalhost() )
{
 if ( ! defined_func("pread") ) exit(0);
 info_t = INFO_LOCAL;
}
else
{
 sock_g = ssh_open_connection();
 if (! sock_g) exit(0);
 info_t = INFO_SSH;
}

# I planned initialy to run 
#  dmidecode -s bios-vendor 
#  dmidecode -s bios-version 
#  dmidecode -s bios-release-date
# Unfortunately, not all versions of dmidecode support the "-s" option.
# dmidecode -t 0 (which gives only BIOS information) is not supported
# everywhere either. So we have to parse the whole output.

# Work around broken $PATH
dirs = make_list( "", "/usr/sbin/", "/usr/local/sbin/", "/sbin/");

keys = make_list("Vendor", "Version", "Release Date");
values = make_list();
found = 0;

foreach d (dirs)
{
 cmd = strcat('LC_ALL=C ', d, 'dmidecode');
 buf = info_send_cmd(cmd: cmd);
 if ('BIOS Information' >< buf)
 {
   lines = split(buf, keep: 0);
   drop_flag = 1;
   foreach l (lines)
   {
     if (ereg(string: l, pattern: '^BIOS Information'))
     {
      drop_flag = 0;
      continue;
     }
     else if (ereg(string: l, pattern: '^[A-Z]')) drop_flag = 1; 
     if (drop_flag) continue;

     foreach k (keys)
     {
       pat = strcat('^[ \t]+', k, '[ \t]*:[  \t]*([^ \t].*)');
       v = eregmatch(string: l, pattern: pat);
       if (! isnull(v)) { values[k] = v[1]; found ++; }
     }
   } 
 }
 if (found > 0) break;
}

if (found || 'BIOS Information' >< buf || 'System Information' >< buf)
  set_kb_item(name: 'Host/dmidecode', value: buf);

uuid = egrep(pattern:'^[\t ]*UUID[ \t]*:', string:buf);
if ( ! isnull(uuid) )
{
  pat = strcat('^[ \t]+UUID[ \t]*:[  \t]*([^ \t].*)');
  v = eregmatch(string: uuid, pattern: pat);
  if ( !isnull(v) )
  {
   uuid = v[1];
  }
  else uuid = NULL;
}

if (! found) exit(0);

report = "";
foreach k (keys(values))
{
 k2 = str_replace(string: k, find: " ", replace: "");
 set_kb_item(name: strcat("BIOS/", k2), value: values[k]);
 report = strcat( report, k, 
 	  	  crap(data: ' ', length: 12 - strlen(k)), ' : ', values[k], '\n');
}

if ( !isnull(uuid) )
{
 report = strcat( report, "UUID", 
 	  	  crap(data: ' ', length: 12 - strlen("UUID")), ' : ', uuid, '\n');

 if ( defined_func('report_xml_tag') ) report_xml_tag(tag:'bios-uuid', value:uuid);
}
security_note(port: 0, extra: report);
