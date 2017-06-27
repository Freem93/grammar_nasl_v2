#TRUSTED 0694ee6625bc71f7fb71b299b7c37d22e634c2673b12df2be1e1295ab9920fe478f24fa7c257fda6733a9d7c6f5c8a1fc9557de79cba01152616ad960a844d3f076260a1fbe3bd21d51813a07b7e213566c90194d159c2da5aa964b1b0bffd03d3a81d1432e746e5a25e2fa1a7020c7c16824d42088c75ce1113cb317a886eb016fde7e881cfbc450e1dca3197a9246c02d277f592934b7f7a4337156fd507416611ca50f578e0517142a2a8ee4dc5819618f4dc00cb0a693254a2da11b68a3bc51d568a51815177e05375bb19d6f0594d606c4c5f560edd5c042795c800fc7455813c772e027ee5dc7e22a4d7edc05a39c45e196f03036c113714de982bf650ebbf0890433d9fc78c74de9838d4c7abe99a3956a93101568482c2512167b416516673e46075727dbc2d2c602b3ae8b0d1f5014a5fe0fdf01183999573063d901523882b52eb7e642fc6db3f8ab90ca808ab567ef6c301fd24c584467e127875f15a816fa39f2899d9156b369f18afcaca0867698cdd79024366c2c7dc6168b3509257d3b1ef5069118ad81b8c586b5ac1e5e61e07fbc8084f6a561db407fc5a752a874772c132371c9ab193d9c0dc4fb4b25bea296451dbb600474f63048c4cbf337e70be9cc3c09f907c5a7c52d5d58502622abd9ee50934ced444355496291e31ad3b397d50a077a32b4ecb091dc2c9f5749ed4149f2e8487ccac3ccc6a48
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(93866);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2016/12/05");

  script_cve_id("CVE-2016-6406");
  script_bugtraq_id(75181);
  script_osvdb_id(144734);
  script_xref(name:"CISCO-BUG-ID", value:"CSCvb26017");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20160922-esa");

  script_name(english:"Cisco Email Security Appliance Internal Testing Interface RCE");
  script_summary(english:"Checks the ESA version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote security appliance is missing a vendor-supplied security
patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Cisco Email Security
Appliance (ESA) running on the remote host is affected by a remote
code execution vulnerability due to the presence of an internal
testing and debugging interface that was not intended to be shipped on
customer-available software releases. An unauthenticated, remote
attacker can exploit this by connecting to the interface, allowing the
attacker to obtain complete control with root-level privileges.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20160922-esa
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5cc98b0e");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvb26017");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant updates referenced in Cisco Security Advisory
cisco-sa-20160922-esa. Alternatively, reboot the ESA device since
rebooting permanently disables the testing and debugging interface.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/09/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/09/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/10/05");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:email_security_appliance");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("cisco_esa_version.nasl");
  script_require_keys("Host/AsyncOS/Cisco Email Security Appliance/DisplayVersion", "Host/AsyncOS/Cisco Email Security Appliance/Version");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

display_ver = get_kb_item_or_exit('Host/AsyncOS/Cisco Email Security Appliance/DisplayVersion');
ver = get_kb_item_or_exit('Host/AsyncOS/Cisco Email Security Appliance/Version');

vuln = FALSE;
if (get_kb_item("Host/local_checks_enabled")) local_checks = TRUE;
else local_checks = FALSE;

# ver is stored as x.y.z.abc rather than x.y.z-abc
if (ver == "9.1.2.023" || ver == "9.1.2.028" || ver == "9.1.2.036")
{
  display_fix = '9.1.2-041';
  vuln = TRUE;
}
else if (ver == "9.7.2.046" || ver == "9.7.2.047" || ver == "9.7.2.054")
{
  display_fix = '9.7.2-065';
  vuln = TRUE;
}
else if (ver == "10.0.0.124" || ver == "10.0.0.125")
{
  display_fix = '10.0.0-203';
  vuln = TRUE;
}
else
  audit(AUDIT_INST_VER_NOT_VULN, 'Cisco ESA', display_ver);

override = FALSE;
# If local checks are enabled, confirm the version of the
# Enrollment Client Component.  Only versions earlier than
# 1.0.2-065 are affected.
# If local checks are not enabled, only report if running a paranoid scan.
if (local_checks && vuln)
{
  vuln = FALSE;

  buf = cisco_command_kb_item("Host/Cisco/Config/ecstatus", "ecstatus");
  if (check_cisco_result(buf) && preg(multiline:TRUE, pattern:"Enrollment Client\s+\d+", string:buf))
  {
    version = eregmatch(pattern:"Enrollment Client\s+([0-9\.-]+)", string:buf);
    if (!empty_or_null(version))
    {
      ecstatus = version[1];
      ver = str_replace(string:ecstatus, find:'-', replace:'.');
      if (ver_compare(ver:ver, fix:'1.0.2.065', strict:FALSE) == -1)
        vuln = TRUE;
      else
        audit(AUDIT_HOST_NOT, "affected because the version of the Enrollment Client Component installed is not affected");
    }
  }
  else if (cisco_needs_enable(buf)) override = TRUE;
}
else if (!local_checks && report_paranoia < 2) vuln = FALSE;

if (vuln)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Installed version : ' + display_ver +
      '\n  Fixed version     : ' + display_fix +
      '\n';
    security_hole(port:0, extra:report+cisco_caveat(override));
  }
  else security_hole(port:0, extra:cisco_caveat(override));
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
