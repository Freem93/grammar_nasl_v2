#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(44657);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2015/10/21 20:34:20 $");

  script_name(english:"Linux Daemons with Broken Links to Executables");
  script_summary(english:"Flags daemons for which the link to the executable is broken.");

  script_set_attribute(
    attribute:"synopsis",
    value:"A daemon on the remote Linux host may need to be restarted."
  );
  script_set_attribute(
    attribute:"description",
    value:
"By examining the '/proc' filesystem on the remote Linux host, Nessus
has identified at least one currently-running daemon for which the
link to the corresponding executable is broken.

This can occur when the executable associated with a daemon is
replaced on disk but the daemon itself has not been restarted.  And if
the changes are security-related, the system may remain vulnerable to
attack until the daemon is restarted.

Alternatively, it could result from an attacker removing files in an
effort to hide malicious activity."
  );
  script_set_attribute(
    attribute:"solution",
    value:
"Inspect each reported daemon to determine why the link to the
executable is broken."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_publication_date", value:"2010/02/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2010-2015 Tenable Network Security, Inc.");

  script_dependencies("process_on_port.nasl");
  script_require_keys("Host/uname", "Host/Listeners/Check");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");


uname = get_kb_item_or_exit("Host/uname");
if ("Linux" >!< uname) audit(AUDIT_HOST_NOT, "Linux");

get_kb_item_or_exit("Host/Listeners/Check");
daemons = get_kb_list_or_exit("Host/Listeners/*");

info = "";
foreach daemon (keys(daemons))
{
  exe = daemons[daemon];
  if (!exe) continue;

  match = eregmatch(pattern:"^(.+) \(deleted\)$", string:exe);
  if (match)
  {
    exe = match[1];

    if (exe[0] == '/') lead_slash = '';
    else lead_slash = '/';

    md5a = get_kb_item('Host/DaemonMD5s' + lead_slash + exe);
    md5b = get_kb_item('Host/PrelinkedDaemons' + lead_slash + exe);

    # should never happen, but check anyways
    if(md5b == "md5_unknown") continue;
    # if it's prelinked, but we don't have an md5 to check if it's been altered,
    # we continue to prevent a false positive (since it most likely *hasn't been altered*)
    if(!isnull(md5b) && isnull(md5a)) continue;

    # prelink image matches process image, so don't report
    if(!isnull(md5a) && !isnull(md5b) && md5a == md5b) continue;

    f = split(daemon, sep:"/", keep:FALSE);
    info += '  - ' + toupper(f[3]) + ' ' + f[2] + ':' + f[4] + ' (' + exe + ')\n';

    # process image does no match prelink verification image,
    # so something has most likely been tampered with
    if(!isnull(md5a) && !isnull(md5b) && md5a != md5b)
      info += '    - Process image does not match prelink verification image. : ' + '\n' +
              '        Process image md5sum              : ' + md5a + '\n' +
              '        Prelink verification image md5sum : ' + md5b + '\n';
  }
}


if (info)
{
  if (report_verbosity > 0)
  {
    if (max_index(split(info)) > 1)
      report = '\n' +
        'The following daemons are associated with broken links to\n' +
        'executables :\n';
    else
      report = '\n' +
        'The following daemon is associated with a broken link to an\n' +
        'executable :\n';

    report += '\n' + info;
    security_hole(port:0, extra:report);
  }
  else security_hole(0);
}
else audit(AUDIT_HOST_NOT, "affected");
