#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(82707);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2016/05/24 13:12:22 $");

  script_cve_id(
    "CVE-2014-3566",
    "CVE-2014-6549",
    "CVE-2014-6585",
    "CVE-2014-6587",
    "CVE-2014-6591",
    "CVE-2014-6593",
    "CVE-2014-6601",
    "CVE-2015-0383",
    "CVE-2015-0395",
    "CVE-2015-0400",
    "CVE-2015-0403",
    "CVE-2015-0406",
    "CVE-2015-0407",
    "CVE-2015-0408",
    "CVE-2015-0410",
    "CVE-2015-0412",
    "CVE-2015-0413",
    "CVE-2015-0421",
    "CVE-2015-0437"
  );
  script_bugtraq_id(
    70574,
    72132,
    72136,
    72137,
    72140,
    72142,
    72146,
    72148,
    72150,
    72154,
    72155,
    72159,
    72162,
    72165,
    72168,
    72169,
    72173,
    72175,
    72176
  );
  script_osvdb_id(
    113251,
    117224,
    117225,
    117226,
    117227,
    117228,
    117229,
    117230,
    117231,
    117232,
    117233,
    117234,
    117235,
    117236,
    117237,
    117238,
    117239,
    117240,
    117241
  );
  script_xref(name:"CERT", value:"577193");
  script_xref(name:"VMSA", value:"2015-0003");

  script_name(english:"VMware vCenter Operations Management Windows JRE Update 1.7.0_76-b13 (VMSA-2015-0003) (POODLE)");
  script_summary(english:"Checks the version of VMware vCenter Operations Manager.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has a virtualization application installed
that is missing a vendor supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The version of VMware vCenter Operations Manager installed on the
remote Windows host has a bundled version of the Java JRE prior to
version 1.7.0_76-b13 (aka 7.0.760.13). It is, therefore, affected by a
man-in-the-middle (MitM) information disclosure vulnerability known as
POODLE. The vulnerability is due to the way SSL 3.0 handles padding
bytes when decrypting messages encrypted using block ciphers in cipher
block chaining (CBC) mode. MitM attackers can decrypt a selected byte
of a cipher text in as few as 256 tries if they are able to force a
victim application to repeatedly send the same data over newly created
SSL 3.0 connections. (CVE-2014-3566)

Additionally, unspecified vulnerabilities also exist in the following
bundled Java components :

  - 2D (CVE-2014-6585, CVE-2014-6591)

  - Deployment (CVE-2015-0403, CVE-2015-0406)

  - Hotspot (CVE-2014-6601, CVE-2015-0383, CVE-2015-0395,
    CVE-2015-0437)

  - Installation (CVE-2015-0421)

  - JAX-WS (CVE-2015-0412)

  - JSSE (CVE-2014-6593)

  - Libraries (CVE-2014-6549, CVE-2014-6587, CVE-2015-0400)

  - RMI (CVE-2015-0408)

  - Security (CVE-2015-0410)

  - Serviceability (CVE-2015-0413)

  - Swing (CVE-2015-0407)

VMware has released a patch that updates the JRE bundled with the
appliance.");
  script_set_attribute(attribute:"see_also", value:"http://www.vmware.com/security/advisories/VMSA-2015-0003.html");
  # http://www.oracle.com/technetwork/java/javase/7u76-relnotes-2389087.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0b2e702a");
  # http://www.oracle.com/technetwork/topics/security/cpujan2015-1972971.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c02f1515");
  script_set_attribute(attribute:"see_also", value:"https://www.imperialviolet.org/2014/10/14/poodle.html");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/~bodo/ssl-poodle.pdf");
  script_set_attribute(attribute:"see_also", value:"https://tools.ietf.org/html/draft-ietf-tls-downgrade-scsv-00");
  script_set_attribute(attribute:"solution", value:"Apply the vendor supplied patches.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/10/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/04/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/04/10");

  script_set_attribute(attribute:"cpe", value:"cpe:/a:vmware:vcenter_operations");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");

  script_dependencies("vmware_vcenter_operations_manager_installed.nbin");
  script_require_keys("SMB/Registry/Enumerated","installed_sw/VMware vCenter Operations Manager");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("smb_func.inc");
include("install_func.inc");

get_kb_item_or_exit("SMB/Registry/Enumerated");

appname = "VMware vCenter Operations Manager";
install = get_single_install(app_name : appname, exit_if_unknown_ver : TRUE);
jrever  = install['jreversion'];
fixed   = "7.0.760.13";
version = install['version'];

if(jrever == UNKNOWN_VER)
  audit(AUDIT_UNKNOWN_APP_VER,appname+"'s redistributed JRE");

if(version !~ "^5\.(7|8)" && version !~ "^6\.")
  audit(AUDIT_NOT_INST, appname + " 5.7.x / 5.8.x / 6.x");

if(ver_compare(ver:jrever,fix:fixed,strict:FALSE) < 0)
{
  port = kb_smb_transport();
  if (report_verbosity > 0)
  {
    report = '\n' +
             '\n  Installed Version : '+install['version']+
             '\n  JRE Path          : '+install['jrepath']+
             '\n  JRE Version       : '+jrever+
             '\n  Fixed JRE Version : '+fixed+
             '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
}
else audit(AUDIT_PATCH_INSTALLED, "VMware-vcops-JRE-SKIP-TLS-HP.exe",appname,version);

