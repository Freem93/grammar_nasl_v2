#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(72829);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/05/20 14:21:44 $");

  script_bugtraq_id(63984, 64602);
  script_osvdb_id(100381, 100382);
  script_xref(name:"EDB-ID", value:"29861");

  script_name(english:"Palo Alto Networks PAN-OS 5.x < 5.0.9 Multiple Vulnerabilities");
  script_summary(english:"Checks the PAN-OS version.");

  script_set_attribute(attribute:"synopsis", value:"The remote host is affected by multiple vulnerabilities.");
  script_set_attribute(
    attribute:"description",
    value:
"The remote host is running a version of Palo Alto Networks PAN-OS 5.x
prior to 5.0.9. It is, therefore, affected by multiple
vulnerabilities :

  - A security bypass vulnerability exists due to a failure
    to properly enforce RADIUS users' permissions. An
    authenticated attacker can exploit this to modify shared
    objects. (Ref# 55287)

  - A cross-site request forgery vulnerability exists due
    to a failure to properly validate HTTP requests to
    certain file upload forms, including
    'import.certificate.php'.

  - Multiple HTML injection vulnerabilities exist due to a
    failure to sanitize user-supplied input to the 'Name',
    'Subject', and 'Issuer' fields in imported certificates.
    An attacker can exploit this to inject arbitrary HTML
    into the device's web interface.
    (Ref# 57343)"
  );
  script_set_attribute(attribute:"see_also", value:"https://live.paloaltonetworks.com/docs/DOC-6244");
  script_set_attribute(attribute:"solution", value:"Upgrade to PAN-OS version 5.0.9 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/11/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/11/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/03/05");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:paloaltonetworks:pan-os");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Palo Alto Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");

  script_dependencies("palo_alto_version.nbin");
  script_require_keys("Host/Palo_Alto/Firewall/Version", "Host/Palo_Alto/Firewall/Full_Version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

app_name = "Palo Alto Networks PAN-OS";
version = get_kb_item_or_exit("Host/Palo_Alto/Firewall/Version");
full_version = get_kb_item_or_exit("Host/Palo_Alto/Firewall/Full_Version");
fix = "5.0.9";

# Ensure sufficient granularity.
if (version !~ "^\d+\.\d+") audit(AUDIT_VER_NOT_GRANULAR, app_name, full_version);

# Only 5.0.x is affected.
if (version !~ "^5\.0($|[^0-9])") audit(AUDIT_INST_VER_NOT_VULN, app_name, full_version);

# Compare version to fix and report as needed.
if (ver_compare(ver:version, fix:fix, strict:FALSE) == -1)
{
  set_kb_item(name:'www/0/XSRF', value:TRUE);
  set_kb_item(name:'www/0/XSS', value:TRUE);

  if (report_verbosity > 0)
  {
    report =
      '\n  Installed version : ' + full_version +
      '\n  Fixed version     : ' + fix +
      '\n';
    security_warning(extra:report, port:0);
  }
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_INST_VER_NOT_VULN, app_name, full_version);
