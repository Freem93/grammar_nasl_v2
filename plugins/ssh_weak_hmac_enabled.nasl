#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(71049);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/12/14 20:33:27 $");

  script_name(english:"SSH Weak MAC Algorithms Enabled");
  script_summary(english:"SSH is configured to allow insecure MAC algorithms.");

  script_set_attribute(attribute:"synopsis", value:
"The remote SSH server is configured to allow MD5 and 96-bit MAC
algorithms.");
  script_set_attribute(attribute:"description", value:
"The remote SSH server is configured to allow either MD5 or 96-bit MAC
algorithms, both of which are considered weak.

Note that this plugin only checks for the options of the SSH server,
and it does not check for vulnerable software versions.");
  script_set_attribute(attribute:"solution", value:
"Contact the vendor or consult product documentation to disable MD5 and
96-bit MAC algorithms.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:N/A:N");

  script_set_attribute(attribute:"plugin_publication_date", value:"2013/11/22");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");

  script_dependencies("ssh_supported_algorithms.nasl");
  script_require_ports("Services/ssh", 22);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

function get_macs(port, type)
{
  local_var alg, algs, macs;

  macs = make_list();

  algs = get_kb_list("SSH/" + port + "/mac_algorithms_" + type);
  if (isnull(algs))
    return macs;

  algs = make_list(algs);
  if (max_index(algs) == 0)
    return macs;

  foreach alg (algs)
  {
    if ("md5" >< alg || "-96" >< alg || "none" >< alg)
      macs = make_list(macs, alg);
  }

  return macs;
}

port = get_service(svc:"ssh", default:22, exit_on_fail:TRUE);

algs_c2s = sort(get_macs(port:port, type:"client_to_server"));
algs_s2c = sort(get_macs(port:port, type:"server_to_client"));
if (max_index(algs_c2s) == 0 && max_index(algs_s2c) == 0)
  audit(AUDIT_NOT_DETECT, "SSH support for known weak MAC algorithms enabled", port);

report = NULL;
if (report_verbosity > 0)
{
  if (max_index(algs_c2s) != 0)
  {
    report +=
      '\nThe following client-to-server Message Authentication Code (MAC) algorithms' +
      '\nare supported : ' +
      '\n' +
      '\n  ' + join(sort(algs_c2s), sep:'\n  ') +
      '\n';
  }

  if (max_index(algs_s2c) != 0)
  {
    report +=
      '\nThe following server-to-client Message Authentication Code (MAC) algorithms' +
      '\nare supported : ' +
      '\n' +
      '\n  ' + join(sort(algs_s2c), sep:'\n  ') +
      '\n';
  }
}

security_note(port:port, extra:report);
