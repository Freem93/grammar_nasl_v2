#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and patch checks in this plugin were 
# extracted from HP patch PHKL_31500. The text itself is
# copyright (C) Hewlett-Packard Development Company, L.P.
#

include("compat.inc");

if (description)
{
  script_id(17400);
  script_version("$Revision: 1.16 $");
  script_cvs_date("$Date: 2014/03/12 15:37:24 $");

  script_cve_id("CVE-2002-1265", "CVE-2004-0744", "CVE-2005-4316");
  script_osvdb_id(8431, 19041);
  script_xref(name:"HP", value:"emr_na-c00579189");
  script_xref(name:"HP", value:"emr_na-c00897380");
  script_xref(name:"HP", value:"emr_na-c00908571");
  script_xref(name:"HP", value:"emr_na-c00951288");
  script_xref(name:"HP", value:"HPSBUX01002");
  script_xref(name:"HP", value:"HPSBUX01020");
  script_xref(name:"HP", value:"HPSBUX01218");
  script_xref(name:"HP", value:"HPSBUX02087");
  script_xref(name:"HP", value:"SSRT2384");
  script_xref(name:"HP", value:"SSRT4688");
  script_xref(name:"HP", value:"SSRT4702");
  script_xref(name:"HP", value:"SSRT4728");

  script_name(english:"HP-UX PHKL_31500 : s700_800 11.23 Sept04 base patch");
  script_summary(english:"Checks for the patch in the swlist output");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote HP-UX host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"s700_800 11.23 Sept04 base patch : 

The remote HP-UX host is affected by multiple vulnerabilities :

  - A potential security vulnerability has been identified
    with HP-UX running RPC services, where the vulnerability
    may be exploited by an unauthorized remote user to
    create a denial of service (DoS). (HPSBUX01020 SSRT2384)

  - A potential vulnerability has been identified in HP-UX
    running the Veritas File System (VxFS) that may allow a
    local authorized user access to unauthorized data.

  - A potential security vulnerability has been identified
    with HP-UX running TCP/IP. The potential vulnerability
    could be exploited remotely to cause a Denial of Service
    (DoS). (HPSBUX02087 SSRT4728)

  - A potential security vulnerability has been found in
    HP-UX running rpc.ypupdated. The vulnerability could be
    exploited to allow remote unauthorized access.
    (HPSBUX01002 SSRT4688)"
  );
  # http://h20000.www2.hp.com/bizsupport/TechSupport/Document.jsp?objectID=c00908571
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3e2239c7"
  );
  # http://h20000.www2.hp.com/bizsupport/TechSupport/Document.jsp?objectID=c00951288
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?87f2ecde"
  );
  # http://h20000.www2.hp.com/bizsupport/TechSupport/Document.jsp?objectID=c00897380
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d460b32c"
  );
  # http://h20000.www2.hp.com/bizsupport/TechSupport/Document.jsp?objectID=c00579189
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d45f7410"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Install patch PHKL_31500 or subsequent."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:hp:hp-ux");

  script_set_attribute(attribute:"patch_publication_date", value:"2004/09/22");
  script_set_attribute(attribute:"patch_modification_date", value:"2007/03/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/03/18");
  script_set_attribute(attribute:"vuln_publication_date", value:"2004/08/10");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2005-2014 Tenable Network Security, Inc.");
  script_family(english:"HP-UX Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/HP-UX/version", "Host/HP-UX/swlist");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("hpux.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/HP-UX/version")) audit(AUDIT_OS_NOT, "HP-UX");
if (!get_kb_item("Host/HP-UX/swlist")) audit(AUDIT_PACKAGE_LIST_MISSING);

if (!hpux_check_ctx(ctx:"11.23"))
{
  exit(0, "The host is not affected since PHKL_31500 applies to a different OS release.");
}

patches = make_list("PHKL_31500");
foreach patch (patches)
{
  if (hpux_installed(app:patch))
  {
    exit(0, "The host is not affected because patch "+patch+" is installed.");
  }
}


flag = 0;
if (hpux_check_patch(app:"InternetSrvcs.INET-ENG-A-MAN", version:"B.11.23")) flag++;
if (hpux_check_patch(app:"InternetSrvcs.INETSVCS2-BOOT", version:"B.11.23")) flag++;
if (hpux_check_patch(app:"InternetSrvcs.INETSVCS2-RUN", version:"B.11.23")) flag++;
if (hpux_check_patch(app:"JFS.JFS-ENG-A-MAN", version:"B.11.23")) flag++;
if (hpux_check_patch(app:"JFS.VXFS-BASE-KRN", version:"B.11.23")) flag++;
if (hpux_check_patch(app:"JFS.VXFS-BASE-RUN", version:"B.11.23")) flag++;
if (hpux_check_patch(app:"JFS.VXFS-PRG", version:"B.11.23")) flag++;
if (hpux_check_patch(app:"LVM.LVM-KRN", version:"B.11.23")) flag++;
if (hpux_check_patch(app:"NFS.KEY-CORE", version:"B.11.23")) flag++;
if (hpux_check_patch(app:"NFS.NFS-64ALIB", version:"B.11.23")) flag++;
if (hpux_check_patch(app:"NFS.NFS-64SLIB", version:"B.11.23")) flag++;
if (hpux_check_patch(app:"NFS.NFS-CORE", version:"B.11.23")) flag++;
if (hpux_check_patch(app:"NFS.NFS-ENG-A-MAN", version:"B.11.23")) flag++;
if (hpux_check_patch(app:"NFS.NFS-KRN", version:"B.11.23")) flag++;
if (hpux_check_patch(app:"NFS.NFS-PRG", version:"B.11.23")) flag++;
if (hpux_check_patch(app:"NFS.NFS-SHLIBS", version:"B.11.23")) flag++;
if (hpux_check_patch(app:"NFS.NFS2-CLIENT", version:"B.11.23")) flag++;
if (hpux_check_patch(app:"NFS.NFS2-CORE", version:"B.11.23")) flag++;
if (hpux_check_patch(app:"NFS.NFS2-PRG", version:"B.11.23")) flag++;
if (hpux_check_patch(app:"NFS.NFS2-SERVER", version:"B.11.23")) flag++;
if (hpux_check_patch(app:"NFS.NIS2-CLIENT", version:"B.11.23")) flag++;
if (hpux_check_patch(app:"NFS.NIS2-CORE", version:"B.11.23")) flag++;
if (hpux_check_patch(app:"NFS.NIS2-SERVER", version:"B.11.23")) flag++;
if (hpux_check_patch(app:"NFS.NISPLUS2-CORE", version:"B.11.23")) flag++;
if (hpux_check_patch(app:"Networking.100BT-KRN", version:"B.11.23")) flag++;
if (hpux_check_patch(app:"Networking.100BT-RUN", version:"B.11.23")) flag++;
if (hpux_check_patch(app:"Networking.LAN-PRG", version:"B.11.23")) flag++;
if (hpux_check_patch(app:"Networking.LAN-RUN", version:"B.11.23")) flag++;
if (hpux_check_patch(app:"Networking.LAN2-KRN", version:"B.11.23")) flag++;
if (hpux_check_patch(app:"Networking.LAN2-RUN", version:"B.11.23")) flag++;
if (hpux_check_patch(app:"Networking.NET-PRG", version:"B.11.23")) flag++;
if (hpux_check_patch(app:"Networking.NET-RUN", version:"B.11.23")) flag++;
if (hpux_check_patch(app:"Networking.NET-RUN-64", version:"B.11.23")) flag++;
if (hpux_check_patch(app:"Networking.NET2-KRN", version:"B.11.23")) flag++;
if (hpux_check_patch(app:"Networking.NET2-RUN", version:"B.11.23")) flag++;
if (hpux_check_patch(app:"Networking.NMS2-KRN", version:"B.11.23")) flag++;
if (hpux_check_patch(app:"Networking.NW-ENG-A-MAN", version:"B.11.23")) flag++;
if (hpux_check_patch(app:"OS-Core.ADMN-ENG-A-MAN", version:"B.11.23")) flag++;
if (hpux_check_patch(app:"OS-Core.C-MIN", version:"B.11.23")) flag++;
if (hpux_check_patch(app:"OS-Core.C-MIN-64ALIB", version:"B.11.23")) flag++;
if (hpux_check_patch(app:"OS-Core.CDFILESYS-KRN", version:"B.11.23")) flag++;
if (hpux_check_patch(app:"OS-Core.CMDS2-AUX", version:"B.11.23")) flag++;
if (hpux_check_patch(app:"OS-Core.CORE-ENG-A-MAN", version:"B.11.23")) flag++;
if (hpux_check_patch(app:"OS-Core.CORE-KRN", version:"B.11.23")) flag++;
if (hpux_check_patch(app:"OS-Core.CORE2-64SLIB", version:"B.11.23")) flag++;
if (hpux_check_patch(app:"OS-Core.CORE2-KRN", version:"B.11.23")) flag++;
if (hpux_check_patch(app:"OS-Core.CORE2-SHLIBS", version:"B.11.23")) flag++;
if (hpux_check_patch(app:"OS-Core.KERN-ENG-A-MAN", version:"B.11.23")) flag++;
if (hpux_check_patch(app:"OS-Core.SYS-ADMIN", version:"B.11.23")) flag++;
if (hpux_check_patch(app:"OS-Core.SYS2-ADMIN", version:"B.11.23")) flag++;
if (hpux_check_patch(app:"OS-Core.UX-CORE", version:"B.11.23")) flag++;
if (hpux_check_patch(app:"OS-Core.UX-FRE-I-MSG", version:"B.11.23")) flag++;
if (hpux_check_patch(app:"OS-Core.UX-FRE-U-MSG", version:"B.11.23")) flag++;
if (hpux_check_patch(app:"OS-Core.UX-GER-I-MSG", version:"B.11.23")) flag++;
if (hpux_check_patch(app:"OS-Core.UX-GER-U-MSG", version:"B.11.23")) flag++;
if (hpux_check_patch(app:"OS-Core.UX-ITA-I-MSG", version:"B.11.23")) flag++;
if (hpux_check_patch(app:"OS-Core.UX-ITA-U-MSG", version:"B.11.23")) flag++;
if (hpux_check_patch(app:"OS-Core.UX-JPN-E-MSG", version:"B.11.23")) flag++;
if (hpux_check_patch(app:"OS-Core.UX-JPN-S-MSG", version:"B.11.23")) flag++;
if (hpux_check_patch(app:"OS-Core.UX-JPN-U-MSG", version:"B.11.23")) flag++;
if (hpux_check_patch(app:"OS-Core.UX-KOR-E-MSG", version:"B.11.23")) flag++;
if (hpux_check_patch(app:"OS-Core.UX-KOR-U-MSG", version:"B.11.23")) flag++;
if (hpux_check_patch(app:"OS-Core.UX-SCH-H-MSG", version:"B.11.23")) flag++;
if (hpux_check_patch(app:"OS-Core.UX-SCH-U-MSG", version:"B.11.23")) flag++;
if (hpux_check_patch(app:"OS-Core.UX-SPA-I-MSG", version:"B.11.23")) flag++;
if (hpux_check_patch(app:"OS-Core.UX-SPA-U-MSG", version:"B.11.23")) flag++;
if (hpux_check_patch(app:"OS-Core.UX-TCH-B-MSG", version:"B.11.23")) flag++;
if (hpux_check_patch(app:"OS-Core.UX-TCH-E-MSG", version:"B.11.23")) flag++;
if (hpux_check_patch(app:"OS-Core.UX-TCH-U-MSG", version:"B.11.23")) flag++;
if (hpux_check_patch(app:"OS-Core.UX2-CORE", version:"B.11.23")) flag++;
if (hpux_check_patch(app:"ProgSupport.C-INC", version:"B.11.23")) flag++;
if (hpux_check_patch(app:"ProgSupport.C2-INC", version:"B.11.23")) flag++;
if (hpux_check_patch(app:"ProgSupport.PAUX-ENG-A-MAN", version:"B.11.23")) flag++;
if (hpux_check_patch(app:"ProgSupport.PROG-AX-64ALIB", version:"B.11.23")) flag++;
if (hpux_check_patch(app:"ProgSupport.PROG-MIN", version:"B.11.23")) flag++;
if (hpux_check_patch(app:"ProgSupport.PROG2-AUX", version:"B.11.23")) flag++;
if (hpux_check_patch(app:"SecurityMon.SECURITY", version:"B.11.23")) flag++;
if (hpux_check_patch(app:"SecurityMon.SECURITY2", version:"B.11.23")) flag++;
if (hpux_check_patch(app:"Streams-TIO.STRTIO2-KRN", version:"B.11.23")) flag++;
if (hpux_check_patch(app:"Streams.STREAMS-32ALIB", version:"B.11.23")) flag++;
if (hpux_check_patch(app:"Streams.STREAMS-64ALIB", version:"B.11.23")) flag++;
if (hpux_check_patch(app:"Streams.STREAMS-64SLIB", version:"B.11.23")) flag++;
if (hpux_check_patch(app:"Streams.STREAMS-MIN", version:"B.11.23")) flag++;
if (hpux_check_patch(app:"Streams.STREAMS2-KRN", version:"B.11.23")) flag++;
if (hpux_check_patch(app:"Streams.STREAMS2-RUN", version:"B.11.23")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:hpux_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
