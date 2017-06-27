#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(82742);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2016/05/24 13:12:23 $");

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

  script_name(english:"VMware Workspace Portal Multiple Java Vulnerabilities (VMSA-2015-0003) (POODLE)");
  script_summary(english:"Checks the version of VMware Workspace Portal.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has a device management application installed that is
affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The VMware Workspace Portal (formerly known as VMware Horizon
Workspace) installed on the remote host is version 2.x prior to 2.1.1.
It is, therefore, affected by a man-in-the-middle (MitM) information
disclosure vulnerability known as POODLE. The vulnerability is due to
the way SSL 3.0 handles padding bytes when decrypting messages
encrypted using block ciphers in cipher block chaining (CBC) mode.
MitM attackers can decrypt a selected byte of a cipher text in as few
as 256 tries if they are able to force a victim application to
repeatedly send the same data over newly created SSL 3.0 connections.
(CVE-2014-3566)

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

  - Swing (CVE-2015-0407)");
  script_set_attribute(attribute:"see_also", value:"https://www.vmware.com/security/advisories/VMSA-2015-0003");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2015/Apr/5");
  # http://www.oracle.com/technetwork/topics/security/cpujan2015-1972971.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c02f1515");
  # Java SE JDK and JRE 7 Update 75
  # http://www.oracle.com/technetwork/java/javase/7u75-relnotes-2389086.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?12e35b07");
  # Java SE JDK and JRE 6 Update 91
  # http://www.oracle.com/technetwork/java/javase/documentation/overview-156328.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?726f7054");
  script_set_attribute(attribute:"see_also", value:"https://www.imperialviolet.org/2014/10/14/poodle.html");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/~bodo/ssl-poodle.pdf");
  script_set_attribute(attribute:"see_also", value:"https://tools.ietf.org/html/draft-ietf-tls-downgrade-scsv-00");
  script_set_attribute(attribute:"solution", value:
"Upgrade to VMware Workspace Portal 2.1.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/10/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/03/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/04/13");

  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:vmware:vmware_horizon_workspace");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:vmware:vmware_workspace_portal");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/VMware Workspace Portal/Version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

app     = "VMware Workspace Portal";
version = get_kb_item_or_exit("Host/VMware Workspace Portal/Version");

if (version !~ "^2([^0-9]|$)") audit(AUDIT_NOT_INST, app + "2.x");
if (version =~ "^2(\.1)?$") audit(AUDIT_VER_NOT_GRANULAR, app, version);

# VMware Workspace Portal affected versions:
if (ver_compare(ver:version, fix:"2.1.1", strict:FALSE) == -1)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 2.1.1' +
      '\n';
    security_hole(port:0, extra:report);
  }
  else security_hole(0);
}
else audit(AUDIT_INST_VER_NOT_VULN, app, version);
