#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(91673);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2016/06/20 17:20:09 $");

  script_osvdb_id(138967);

  script_name(english:"Palo Alto Networks User-ID Agent < 7.0.4 TLS-Secured API Invocation Credential Disclosure (PAN-SA-2016-0007)");
  script_summary(english:"Checks the Palo Alto Networks User-ID agent version.");

  script_set_attribute(attribute:"synopsis", value:
"The Palo Alto Networks User-ID agent installed on the remote host is
affected by a credential disclosure vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Palo Alto Networks User-ID agent installed on the
remote Windows host is prior to 7.0.4. It is, therefore, affected by a
flaw that allows a TLS-secured API call to return encrypted
credentials to the domain account configured on the User-ID agent,
which has read-only rights for Security Event Logs on Domain
Controllers. An authenticated, remote attacker with access to the
User-ID agent Service TCP port can exploit this to gain access to
credential information.");
  script_set_attribute(attribute:"see_also", value:"https://securityadvisories.paloaltonetworks.com/Home/Detail/40");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Palo Alto Networks User-ID agent version 7.0.4");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/05/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/05/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/06/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("palo_alto_uidagent_detect.nbin");
  script_require_keys("installed_sw/Palo Alto User-ID Agent");
  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("install_func.inc");

sw = "Palo Alto User-ID Agent";
install = get_single_install(app_name:sw, exit_if_unknown_ver:TRUE);
ver = install["version"];
path = install["path"];
flag = FALSE;
fix = "7.0.4";

# Check Granularity
if(ver =~ "^7(\.0)?([^0-9\.]|$)") audit(AUDIT_VER_NOT_GRANULAR, sw, ver);

if (ver_compare(ver:ver, fix:fix, strict:FALSE) < 0){
  flag = TRUE;
}
else audit(AUDIT_INST_VER_NOT_VULN, sw, ver);

if (flag)
{
  port = get_kb_item("SMB/transport");
  if (isnull(port)) 
  port = 445;

  report =
    '\n  Product           : ' + sw +
    '\n  Path              : ' + path +
    '\n  Installed version : ' + ver +
    '\n  Fixed version     : ' + fix +
    '\n';
  security_report_v4(severity:SECURITY_WARNING, port:port, extra:report);
}
else audit(AUDIT_INST_VER_NOT_VULN, sw, ver);
