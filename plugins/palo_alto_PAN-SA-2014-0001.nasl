#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(73138);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/05/03 20:51:50 $");

  script_bugtraq_id(65886);
  script_osvdb_id(102738);

  script_name(english:"Palo Alto Networks PAN-OS 4.1.x < 4.1.16 / 5.0.x < 5.0.10 / 5.1.x < 5.1.5 API Key Bypass Flaw");
  script_summary(english:"Checks PAN-OS version");

  script_set_attribute(attribute:"synopsis", value:"The remote host is affected by an API key bypass flaw.");
  script_set_attribute(
    attribute:"description",
    value:
"The remote host is running a version of Palo Alto Networks PAN-OS
prior to 4.1.16 / 5.0.10 / 5.1.5. It is, therefore, affected by an API
key bypass flaw which allows a remote attacker to bypass the XML API
key for a session that has already been authorized. 

Note that Nessus has not tested for this issue but has instead relied
only on the application's self-reported version number."
  );
  script_set_attribute(attribute:"see_also", value:"https://securityadvisories.paloaltonetworks.com/Home/Detail/21");
  script_set_attribute(attribute:"solution", value:"Upgrade to PAN-OS version 4.1.16 / 5.0.10 / 5.1.5 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/01/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/01/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/03/21");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:paloaltonetworks:pan-os");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Palo Alto Local Security Checks");

  script_dependencies("palo_alto_version.nbin");
  script_require_keys("Host/Palo_Alto/Firewall/Version", "Host/Palo_Alto/Firewall/Full_Version");

  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

app_name = "Palo Alto Networks PAN-OS";
version = get_kb_item_or_exit("Host/Palo_Alto/Firewall/Version");
full_version = get_kb_item_or_exit("Host/Palo_Alto/Firewall/Full_Version");
fix = NULL;

# Ensure sufficient granularity.
if (version !~ "^\d+\.\d+") audit(AUDIT_VER_NOT_GRANULAR, app_name, full_version);

if (version =~ "^5\.0($|[^0-9])")
  fix = "5.0.10";
else if (version =~ "^5\.1($|[^0-9])")
  fix = "5.1.5";
else
  fix = "4.1.16";

# Compare version to fix and report as needed.
if (ver_compare(ver:version, fix:fix, strict:FALSE) == -1)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Installed version : ' + full_version +
      '\n  Fixed version     : ' + fix +
      '\n';
    security_note(extra:report, port:0);
  }
  else security_note(0);

  exit(0);
}
else audit(AUDIT_INST_VER_NOT_VULN, app_name, full_version);
