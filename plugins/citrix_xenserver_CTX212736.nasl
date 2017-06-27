#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(91352);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2017/02/08 14:50:45 $");

  script_cve_id(
    "CVE-2016-2107",
    "CVE-2016-2108",
    "CVE-2016-3710",
    "CVE-2016-3712"
  );
  script_bugtraq_id(90314, 90316);
  script_osvdb_id(
    137896,
    137900,
    138373,
    138374
  );
  script_xref(name:"EDB-ID", value:"39768");

  script_name(english:"Citrix XenServer Multiple Vulnerabilities (CTX212736)");
  script_summary(english:"Checks for patches.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Citrix XenServer running on the remote host is affected
by multiple vulnerabilities in the bundled versions of OpenSSL and
QEMU :

  - Multiple flaws exist in the bundled version of OpenSSL
    in the aesni_cbc_hmac_sha1_cipher() and
    aesni_cbc_hmac_sha256_cipher() functions that are
    triggered when the connection uses an AES-CBC cipher and
    AES-NI is supported by the server. A man-in-the-middle
    attacker can exploit these issues to conduct a padding
    oracle attack, resulting in the ability to decrypt the
    network traffic. (CVE-2016-2107)

  - A remote code execution vulnerability exists in the
    bundled version of OpenSSL in the ASN.1 encoder
    component due to an underflow condition that occurs when
    attempting to encode the value zero represented as a
    negative integer. An unauthenticated, remote attacker
    can exploit this to corrupt memory, resulting in the
    execution of arbitrary code. (CVE-2016-2108)

  - An out-of-bounds write error exists in the bundled
    version of QEMU in the vga_update_memory_access()
    function that is triggered when access nodes are changed
    after the register bank has been set. An attacker on the
    guest can exploit this to execute arbitrary code with
    the privileges of the host's QEMU process.
    (CVE-2016-3710)

  - An integer overflow condition exists in the bundled
    version of QEMU in the vbe_update_vgaregs() function
    that is triggered when setting certain VGA registers
    while in VBE mode. An attacker on the guest can
    exploit this to crash the host's QEMU process.
    (CVE-2016-3712)");
  script_set_attribute(attribute:"see_also", value:"https://support.citrix.com/article/CTX212736");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate hotfix as referenced in the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date",value:"2016/05/03");
  script_set_attribute(attribute:"patch_publication_date",value:"2016/05/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/05/27");

  script_set_attribute(attribute:"plugin_type",value:"local");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:citrix:xenserver");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2016-2017 Tenable Network Security, Inc.");

  script_dependencies("citrix_xenserver_version.nbin");
  script_require_keys("Host/XenServer/version", "Host/local_checks_enabled");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

app_name = "Citrix XenServer";
version = get_kb_item_or_exit("Host/XenServer/version");
get_kb_item_or_exit("Host/local_checks_enabled");
patches = get_kb_item("Host/XenServer/patches");
vuln = FALSE;
fix = '';

# We will do our checks within the branches since there can be SP releases
# special treatment.
if (version == "6.0.0")
{
  fix = "XS60E061";
  if (fix >!< patches) vuln = TRUE;
}
else if (version == "6.0.2")
{
  fix = "XS602E055 or XS602ECC032";
  if (("XS602E055" >!< patches) && ("XS602ECC032" >!< patches)) vuln = TRUE;
}
else if (version =~ "^6\.1\.")
{
  fix = "XS61E070";
  if (fix >!< patches) vuln = TRUE;
}
else if (version =~ "^6\.2\.")
{
  fix = "XS62ESP1044";
  if (fix >!< patches) vuln = TRUE;
}
else if (version =~ "^6\.5\.")
{
  fix = "XS65ESP1032 and XS65ESP1033";
  if (("XS65ESP1032" >!< patches) || ("XS65ESP1033" >!< patches)) vuln = TRUE;
}
else audit(AUDIT_INST_VER_NOT_VULN, app_name, version);

if (vuln)
{
  port = 0;
  report = report_items_str(
    report_items:make_array(
      "Installed version", version,
      "Missing hotfix", fix
    ),
    ordered_fields:make_list("Installed version", "Missing hotfix")
  );
  security_report_v4(port:port, severity:SECURITY_HOLE, extra:report);
}
else audit(AUDIT_PATCH_INSTALLED, fix);
