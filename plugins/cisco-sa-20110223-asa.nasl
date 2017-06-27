#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
  script_id(52586);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2014/03/05 23:17:30 $");
 
  script_cve_id("CVE-2011-0393", "CVE-2011-0394", "CVE-2011-0395", "CVE-2011-0396");
  script_bugtraq_id(46518, 46524);
  script_osvdb_id(72582, 72584, 72585, 72586);
  script_xref(name:"CISCO-BUG-ID", value:"CSCtg66583");
  script_xref(name:"CISCO-BUG-ID", value:"CSCtg69457");
  script_xref(name:"CISCO-BUG-ID", value:"CSCtj04707");
  script_xref(name:"CISCO-BUG-ID", value:"CSCtk12352");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20110223-asa");

  script_name(english:"Cisco ASA 5500 Series Multiple Vulnerabilities (cisco-sa-20110223-asa)");
  script_summary(english:"Checks the version of the remote ASA.");
 
  script_set_attribute(
    attribute:"synopsis",
    value:"The remote security device is missing a vendor-supplied security patch."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote Cisco ASA device is missing a security patch and may be
affected by the following issues :

  - When configured for transparent firewall mode, a packet
    buffer exhaustion vulnerability could cause the appliance
    to stop forwarding traffic. (CVE-2011-0393)

  - When SCCP inspection is enabled, a malformed SCCP
    message could cause the appliance to reload.
    (CVE-2011-0394)

  - If both RIP and the Cisco Phone Proxy feature are enabled,
    the appliance may reload when processing valid
    RIP updates. (CVE-2011-0395)

  - When the appliance is configured as a local CA server,
    unauthorized users can obtain sensitive data without
    providing authentication. (CVE-2011-0396)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?acf4073e"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?1b415a2e"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Apply the appropriate patch (see plugin output)."
  );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:N/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"vuln_publication_date",value:"2011/02/23");
  script_set_attribute(attribute:"patch_publication_date",value:"2011/02/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/03/09");
  script_set_attribute(attribute:"plugin_type",value:"local");
  script_set_attribute(attribute:"cpe",value:"cpe:/h:cisco:asa_5500");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:cisco:adaptive_security_appliance_software");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2014 Tenable Network Security, Inc.");
  script_family(english:"CISCO");
 
  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/Cisco/ASA", "Host/Cisco/ASA/model");
  exit(0);
}


include("cisco_func.inc");
include("audit.inc");

asa = get_kb_item_or_exit('Host/Cisco/ASA');
model = get_kb_item_or_exit('Host/Cisco/ASA/model');
ver = extract_asa_version(asa);
if (isnull(ver)) audit(AUDIT_FN_FAIL, 'extract_asa_version');

if (model !~ '^55[0-9][0-9]')
  audit(AUDIT_HOST_NOT, 'ASA 5500');

# first check 7.1 (the recommendation is to migrate to 7.2 and upgrade)
if (ver =~ '^7\\.1($|[^0-9])')
{
  report =
    '\n  Installed release : ' + ver +
    '\n  Fixed release     : 7.2(5.2)\n';
  security_hole(port:0, extra:report);
  exit(0);
}

# compare the ASA version versus all recommended releases.  The
# comparison is only made if the major versions match up
recommended_releases = make_list('7.0(8.12)', '7.2(5.2)', '8.0(5.23)', '8.1(2.49)', '8.2(4.1)', '8.3(2.13)', '8.4(1)');
foreach patch (recommended_releases)
{
  if (check_asa_release(version:ver, patched:patch))
  {
    report =
      '\n  Installed release : ' + ver +
      '\n  Fixed release     : ' + patch + '\n';
    security_hole(port:0, extra:report);
    exit(0);
  }
}

audit(AUDIT_INST_VER_NOT_VULN, 'ASA', ver);

