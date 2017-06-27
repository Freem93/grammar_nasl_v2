#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(90317);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/12/14 20:33:27 $");

  script_name(english:"SSH Weak Algorithms Supported");
  script_summary(english:"Checks which algorithms are supported and considered weak.");

  script_set_attribute(attribute:"synopsis", value:
"The remote SSH server is configured to allow weak encryption
algorithms or no algorithm at all.");
  script_set_attribute(attribute:"description", value:
"Nessus has detected that the remote SSH server is configured to use
the Arcfour stream cipher or no cipher at all. RFC 4253 advises
against using Arcfour due to an issue with weak keys.");
  script_set_attribute(attribute:"solution", value:
"Contact the vendor or consult product documentation to remove the weak
ciphers.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_attribute(attribute:"see_also", value:"https://tools.ietf.org/html/rfc4253#section-6.3");

  script_set_attribute(attribute:"plugin_publication_date", value:"2016/04/04");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("ssh_supported_algorithms.nasl");
  script_require_ports("Services/ssh", 22);

  exit(0);
}

include("audit.inc");
include("byte_func.inc");
include("global_settings.inc");
include("misc_func.inc");

# Return a list of weak algorithms detected
function check_algs(algs)
{
  local_var weak_algs, detected, alg, w_alg;

  weak_algs = make_list("arcfour", "none");
  detected  = make_list();

  foreach alg (algs)
  {
    foreach w_alg (weak_algs)
    {
      if (w_alg >< alg) detected = make_list(detected, alg);
    }
  }

  if (empty(detected)) return NULL;
  else return detected;
}

port = get_service(svc:"ssh", default:22, exit_on_fail:TRUE);

algs_s2c = get_kb_list("SSH/"+port+"/encryption_algorithms_server_to_client");
algs_c2s = get_kb_list("SSH/"+port+"/encryption_algorithms_client_to_server");

if (empty_or_null(algs_s2c) && empty_or_null(algs_c2s))
  exit(0, "No supported SSH encryption algorithms were detected on the remote host.");

report = '';

detected = NULL;
if (!empty_or_null(algs_s2c)) detected = check_algs(algs:make_list(algs_s2c));
if (!empty_or_null(detected))
  report +=
    '\nThe following weak server-to-client encryption algorithms are supported : ' +
    '\n' +
    '\n  ' + join(sort(detected), sep:'\n  ') +
    '\n';

detected = NULL;
if (!empty_or_null(algs_c2s)) detected = check_algs(algs:make_list(algs_c2s));
if (!empty_or_null(detected))
  report +=
    '\nThe following weak client-to-server encryption algorithms are supported : ' +
    '\n' +
    '\n  ' + join(sort(detected), sep:'\n  ') +
    '\n';

if (empty(report)) audit(AUDIT_NOT_DETECT, "SSH support for known weak encryption algorithms", port);

security_report_v4(port:port, extra:report, severity:SECURITY_WARNING);
