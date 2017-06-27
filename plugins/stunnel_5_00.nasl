#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(73212);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/07/29 16:23:47 $");

  script_cve_id("CVE-2014-0016");
  script_bugtraq_id(65964);
  script_osvdb_id(104043);

  script_name(english:"stunnel < 5.00 PRNG State Security Weakness");
  script_summary(english:"Checks version of stunnel.exe.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a program that is affected by a
security weakness.");
  script_set_attribute(attribute:"description", value:
"The version of stunnel installed on the remote host is prior to
version 5.00. It is, therefore, affected by a security weakness due to
the PRNG state not being reset for new connections where the server
forks. A remote attacker can exploit this issue to disclose sensitive
information, such as the private key used for EC (ECDSA) or DSA
certificates.

Note that Nessus has not tested for this issue but has instead relied
only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"http://stunnel.org/?page=sdf_ChangeLog");
  # https://www.stunnel.org/pipermail/stunnel-announce/2014-March/000074.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6daa163b");
  script_set_attribute(attribute:"solution", value:"Upgrade to stunnel version 5.00 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/03/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/03/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/03/26");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:stunnel:stunnel");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");

  script_dependencies("stunnel_installed.nasl");
  script_require_keys("installed_sw/stunnel");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("install_func.inc");

app = 'stunnel';
install = get_single_install(app_name:app, exit_if_unknown_ver:TRUE);

version = install["version"];
path = install["path"];

# Affected < 5.00
if (version =~ "^[0-4]($|[^0-9])")
{
  port = get_kb_item("SMB/transport");
  if (!port) port = 445;

  report =
    '\n  Path              : ' + path +
    '\n  Installed version : ' + version +
    '\n  Fixed version     : 5.00\n';
  security_report_v4(severity:SECURITY_WARNING, port:port, extra:report);
}
else audit(AUDIT_INST_PATH_NOT_VULN, app, version, path);
