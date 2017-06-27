#TRUSTED 0af15db617c203ae0b2ba9f521f22dad33aed8accccc4948ae2825e52d47b22e4e4a987c8de9079babffbad3bda3572b815701ae86021a51ab994cf818100d93a5bc3513f4f5c16359b598702c31b3da7050d1dd2db9ad84ee089209f95a3b144ad4a1dceee6ce55c842ce4f10f4b8bf1cb6e4ed227000747e0b204988174a56ea8441efb1b4efd60b9f2276eea8f6f20c9357ecdb72d4b5635f56acf2655e8991897b70df763203da2be4231c1b76f0a9d2222e5e2b5a1d7cbcd0c6aad872ac16ae9ef41f6e0f2075fa5ca471a1be5863c7039a46d4e066a6eac5f4e16596579b0799a99613fc1972cf495df2e145315f6d199881cb76c7e38bab6f67ef5cfa74d649067315af24cb49d9d94406d0f7d53f74cf40208620bdcdd8fe46c362c13cf5d55c133b5f62d3f26684d423ad8d866a0aaf7e6d3dc31f115f07e1f5dc7cc356ae267e4f783bf272cf210fee90f5553eeddd9e78c3e59ba457b398429943506f6193a84e90eb6a1edddd472086322d590df73e35ac94245a2d71fccf0c941c25747bfb23bad3b246c2f9ec58ce49a2509be10771fe2a1fc3cf11928531aa1c38d78c55f2df7c82a1d6a357c26f8db6e1df6f95d026bc4adfd13ae300df4bf838b36a5e0f437397efefdf5528d4c32a71c1ce9eb3ee5e98be249e8a96e867547a4b6aba59bec259cb5f024a9e90d4f5bde0c0b21720df470e03b50e7bc0ef
#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(33851);
 script_version("1.11");
 script_set_attribute(attribute:"plugin_modification_date", value: "2016/11/17");

 script_name(english: "Network daemons not managed by the package system");
 
 script_set_attribute(attribute:"synopsis", value:
"Some daemon processes on the remote host are associated with programs
that have been installed manually." );
 script_set_attribute(attribute:"description", value:
"Some daemon processes on the remote host are associated with programs
that have been installed manually. 

System administration best practice dictates that an operating
system's native package management tools be used to manage software
installation, updates, and removal whenever possible." );
 script_set_attribute(attribute:"solution", value:
"Use packages supplied by the operating system vendor whenever
possible. 

And make sure that manual software installation agrees with your
organization's acceptable use and security policies." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:S/C:N/I:P/A:N");
 script_set_attribute(attribute:"plugin_publication_date", value: "2008/08/08");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"agent", value:"unix");
 script_end_attributes();

 script_summary(english: "Checks that running daemons are registered with RPM / dpkg / emerge");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2008-2016 Tenable Network Security, Inc.");
 script_family(english: "Misc.");
 script_require_keys("Host/uname");
 script_dependencies("ssh_get_info.nasl", "process_on_port.nasl");
 exit(0);
}

include("ssh_func.inc");
include("telnet_func.inc");
include("hostlevel_funcs.inc");


uname = get_kb_item("Host/uname");
if ( ! uname || "Linux" >!< uname ) exit(0);


pkg_system = NULL;

# We cannot solely rely on the fact that the 'rpm' command is installed (it can be 
# installed on Debian or Gentoo for instance).
#
# Although there are other RPM based distros, we do not support them to 
# avoid FP.
v = get_kb_list('Host/*/rpm-list');
if (! isnull(v)) pkg_system = "RPM";
else
{
 v = get_kb_list('Host/*/dpkg-l');
 if (! isnull(v)) pkg_system = 'dpkg';
 else
 {
  v = get_kb_item('Host/Gentoo/qpkg-list');
  if (strlen(v) > 0) pkg_system = "emerge";
  else
  {
   exit(0);	# Unsupported distro
  }
 }
}

v = NULL;	# Free memory


full_path_l = get_kb_list("Host/Daemons/*/*/*");
if (isnull(full_path_l)) exit(0);
full_path_l = make_list(full_path_l);
if (max_index(full_path_l) == 0) exit(0);

# We may support other protocols here
if ( islocalhost() )
 info_t = INFO_LOCAL;
else
{
 ret = ssh_open_connection();
 if (! ret ) exit(0);
 info_t = INFO_SSH;
}

prev = NULL;
bad = ""; bad_n = 0;
foreach d (sort(full_path_l))
  if (strlen(d) > 0 && d != prev && d[0] == '/' )
  {
    match = eregmatch(pattern:"^(.+) \(deleted\)$", string:d);
    if (match) d = match[1];
    
    prev = d;
    d = str_replace(find:"'", replace:"'\''", string:d);
    if (pkg_system == 'RPM')
    {
      buf = info_send_cmd(cmd: strcat('LC_ALL=C rpm -q -f \'', d, '\' || echo FileIsNotPackaged'));
      if ("FileIsNotPackaged" >< buf || strcat("file ", d, " is not by any package") >< buf)
      {
        bad = strcat(bad, d, '\n');
	bad_n ++;
      }
    }
    else if ( pkg_system == "dpkg" )
    {
      buf = info_send_cmd(cmd: strcat('LC_ALL=C dpkg -S \'', d, '\' || echo FileIsNotPackaged'));
      if ("FileIsNotPackaged" >< buf || strcat("dpkg: ", d, " not found.") >< buf)
      {
        bad = strcat(bad, d, '\n');
	bad_n ++;
      }
    }
    else if (pkg_system == "emerge")
    {
      buf = info_send_cmd(cmd: strcat('LC_ALL=C fgrep -q \'obj ', d, ' \' /var/db/pkg/*/*/CONTENTS || echo FileIsNotPackaged'));
      if ("FileIsNotPackaged" >< buf)
      {
        bad = strcat(bad, d, '\n');
	bad_n ++;
      }
    }
    else exit(0); # ?
  }

if (bad_n > 0)
{
  if (bad_n <= 1)
    report = 'The following running daemon is not managed by ';
  else
    report = 'The following running daemons are not managed by ';
  report = strcat(report, pkg_system, ' :\n\n', bad);
  security_note(port: 0, extra: '\n' + report);
}
