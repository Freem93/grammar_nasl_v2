#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(87673);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/01/06 22:50:54 $");

  script_cve_id(
    "CVE-2014-1207",
    "CVE-2014-1208"
  );
  script_bugtraq_id(
    64994,
    64995
  );
  script_osvdb_id(
    102196,
    102197
  );
  script_xref(name:"VMSA", value:"2014-0001");

  script_name(english:"VMware ESX / ESXi Multiple DoS (VMSA-2014-0001)");
  script_summary(english:"Checks the version and build numbers of the remote host.");

  script_set_attribute(attribute:"synopsis", value:
"The remote VMware ESX / ESXi host is missing a security-related patch.");
  script_set_attribute(attribute:"description", value:
"The remote VMware ESX / ESXi host is affected by multiple denial of
service vulnerabilities :

    - A denial of service vulnerability exists due to a NULL
      pointer deference flaw when handling Network File Copy
      (NFC) traffic. An unauthenticated, remote attacker can
      exploit this by intercepting and modifying the traffic
      between the ESX / ESXi host and the client.
      (CVE-2014-1207)

    - A flaw exists due to improper handling of invalid
      ports. An unauthenticated attacker on an adjacent
      network can exploit this to cause VMX processing to
      fail, resulting in a partial denial of service.
      (CVE-2014-1208)");
  script_set_attribute(attribute:"see_also", value:"https://www.vmware.com/security/advisories/VMSA-2014-0001");
  script_set_attribute(attribute:"see_also", value:"http://lists.vmware.com/pipermail/security-announce/2014/000231.html");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the vendor advisory that
pertains to ESX version 4.0 / 4.1 and ESXi version 4.0 / 4.1 / 5.0 /
5.1.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/01/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/01/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/12/30");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esx:4.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esx:4.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esxi:4.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esxi:4.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esxi:5.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esxi:5.1");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");

  script_dependencies("vmware_vsphere_detect.nbin");
  script_require_keys("Host/VMware/version", "Host/VMware/release");
  script_require_ports("Host/VMware/vsphere");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

ver = get_kb_item_or_exit("Host/VMware/version");
rel = get_kb_item_or_exit("Host/VMware/release");
port = get_kb_item_or_exit("Host/VMware/vsphere");
esx = '';

if ("ESX" >!< rel)
  audit(AUDIT_OS_NOT, "VMware ESX/ESXi");

extract = eregmatch(pattern:"^(ESXi?) (\d\.\d).*$", string:ver);
if (isnull(extract))
  audit(AUDIT_UNKNOWN_APP_VER, "VMware ESX/ESXi");
else
{
  esx = extract[1];
  ver = extract[2];
}

# fixed build numbers are the same for ESX and ESXi
fixes = make_array(
          "4.0", "1335992",
          "4.1", "1363503",
          "5.0", "1311175", #1311177 is "security only"
          "5.1", "1483097"
        );

sec_fixes = make_array(
              "5.0", "1311177"
             );

fix = FALSE;
fix = fixes[ver];
sec_fix = FALSE;
sec_fix = sec_fixes[ver];

# get the build before checking the fix for the most complete audit trail
extract = eregmatch(pattern:'^VMware ESXi?.* build-([0-9]+)$', string:rel);
if (isnull(extract))
  audit(AUDIT_UNKNOWN_BUILD, "VMware " + esx, ver);

build = int(extract[1]);

# if there is no fix in the array, fix is FALSE
if (!fix)
  audit(AUDIT_INST_VER_NOT_VULN, esx, ver, build);

if (build < fix)
{
  if (sec_fix)
    fix = fix + " / " + sec_fix;

  if (report_verbosity > 0)
  {
    report = '\n  Version         : ' + esx + " " + ver +
             '\n  Installed build : ' + build +
             '\n  Fixed build     : ' + fix +
             '\n';
    security_warning(port:port, extra:report);
  }
  else
    security_warning(port:port);

  exit(0);
}
else
  audit(AUDIT_INST_VER_NOT_VULN, "VMware " + esx, ver, build);
