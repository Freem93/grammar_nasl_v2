#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(56631);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2013/02/05 16:16:18 $");

  script_cve_id(
    "CVE-2011-3298",
    "CVE-2011-3299",
    "CVE-2011-3300",
    "CVE-2011-3301",
    "CVE-2011-3302",
    "CVE-2011-3303",
    "CVE-2011-3304"
  );
  script_bugtraq_id(49951, 49952, 49956);
  script_osvdb_id(76085, 76086, 76087, 76088, 76089, 76090, 76091);
  script_xref(name:"CISCO-BUG-ID", value:"CSCtl67486");
  script_xref(name:"CISCO-BUG-ID", value:"CSCto40365");
  script_xref(name:"CISCO-BUG-ID", value:"CSCto92380");
  script_xref(name:"CISCO-BUG-ID", value:"CSCto92398");
  script_xref(name:"CISCO-BUG-ID", value:"CSCtq06062");
  script_xref(name:"CISCO-BUG-ID", value:"CSCtq06065");
  script_xref(name:"CISCO-BUG-ID", value:"CSCtq57697");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20111005-asa");

  script_name(english:"Cisco ASA 5500 Series Multiple Vulnerabilities (cisco-sa-20111005-asa)");
  script_summary(english:"Checks the version of the remote ASA.");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote security device is missing a vendor-supplied security
patch."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote Cisco ASA is missing a security patch and may be affected
by the following issues :

  - When MSN IM inspection is enabled, inspecting malformed
    transit traffic could cause the device to reload.
    (CVE-2011-3304)

  - TACACS+ authentication can be bypassed by an attacker
    with access between the ASA and the TACACS+ server.
    (CVE-2011-3298)

  - Four DoS vulnerabilities in the SunRPC inspection
    engine can be triggered by specially crafted
    UDP traffic, causing the device to reload.
   (CVE-2011-3299, CVE-2011-3300, CVE-2011-3301, CVE-2011-3302)

  - When ILS inspection is enabled, inspecting malformed
    transit traffic could cause the device to reload,
    resulting in a sustained DoS condition. (CVE-2011-3303)"
  );
  script_set_attribute(attribute:"see_also",value:"http://www.nessus.org/u?9309dab6");
  script_set_attribute(
    attribute:"solution",
    value:"Apply the appropriate Cisco ASA patch (see plugin output)."
  );
 script_set_cvss_base_vector("CVSS2#AV:A/AC:M/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"vuln_publication_date", value:"2011/10/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/10/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/10/25");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:asa_5500");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:adaptive_security_appliance_software");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2011-2013 Tenable Network Security, Inc.");
 
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
    '\n  Fixed release     : 7.2(5.4)\n';
  security_hole(port:0, extra:report);
  exit(0);
}

# then check 8.1 (the recommendation is to migrate to 8.2 or later and upgrade)
if (ver =~ '^8\\.1($|[^0-9])')
{
  report =
    '\n  Installed release : ' + ver +
    '\n  Fixed release     : migrate to 8.2 or later and apply patches\n';
  security_hole(port:0, extra:report);
  exit(0);
}

# compare the ASA version versus all recommended releases.  The
# comparison is only made if the major versions match up
recommended_releases = make_list('7.0(8.13)', '7.2(5.4)', '8.0(5.25)', '8.2(5.11)', '8.3(2.23)', '8.4(2.7)', '8.5(1.1)');
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

