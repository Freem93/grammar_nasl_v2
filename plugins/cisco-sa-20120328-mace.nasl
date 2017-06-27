#TRUSTED 1fb9443c062af63ca529ce8f54c668c45b8088d218b7f28663255b2b5740d84b108b477717726c0abfabf78c23cec2657c631a6ee0382e51d6f74123dfe929789b7ad37e30b9c12f98ee1eac9d34e49bef8de999eba60796089d12cf2832bc59ae70a7fa9741a51f469660af96fa44a9f34dc9d39bcf229e94bd3d00457cb1fd02dd4d58fcb57ff33e3a959b36955850ab93940f0ff35adf484b17154cd7e9b6965261de2ab3d35526bb69b281ba4acf9910656c69db01167091192bd413b9cce193e72a3ac94701b8c86341609dfb5280c296481d880f1685025cf9c004912057c63250c0f1762b57b1295b71a8b8c3a45813c3b9e1c34ca3b0b8de0592e5a80faa974ddc1c91476eb6299836ca452f90ac41658ad19a197795cce52453bc0ed8f23919f9217cf24652c5dae35d1f9df947aeb6d468dc6a2a578a6e2fab65aef187dd7cfef6a5d557ae910f4dba4c425abbf48610131a8717f51e6f840d4b4cc4dce12be9a507cc4a8290970567c338a1920045059a68c31ae02c5e56052cde345de2e995be7a77eeca994a5a29bf69004f0169ebf04bc18111e6c7164ae2098ea7aec22c92b40da499835f9744dbb30fd1bd4da2eed6f0af49f081377e7314b333995f7c87f0781294cfb7cac9479b16b92cd91d7c5631edb3b20d963a014ac72f87f5ee107dc36738db94e404fb3365bd22e0a1cd238d3bdf7be966be34ce
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(58567);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2015/06/19");

  script_cve_id("CVE-2012-1312", "CVE-2012-1314");
  script_bugtraq_id(52751);
  script_osvdb_id(80702, 80703);
  script_xref(name:"CISCO-BUG-ID", value:"CSCtq64987");
  script_xref(name:"CISCO-BUG-ID", value:"CSCtt45381");
  script_xref(name:"CISCO-BUG-ID", value:"CSCtu57226");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20120328-mace");

  script_name(english:"Cisco IOS Software Traffic Optimization Features Multiple DoS");
  script_summary(english:"Checks the IOS version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The version of Cisco IOS installed on the remote device is affected
by multiple denial of service vulnerabilities due to message parsing
flaws related to the Wide Area Application Services (WAAS) Express
feature and the Measurement, Aggregation, and Correlation Engine
(MACE) feature. A remote, unauthenticated attacker can exploit these
flaws, via crafted requests, to cause a device reload or consumption
of memory, resulting in a denial of service condition.");
  # http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20120328-mace
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?26112a15");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant patch referenced in Cisco Security Advisory
cisco-sa-20120328-mace.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/03/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/03/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/04/02");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value: "cpe:/o:cisco:ios");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2015 Tenable Network Security, Inc.");
  script_family(english:"CISCO");

  script_dependencies("cisco_ios_version.nasl");
  script_require_keys("Host/Cisco/IOS/Version");
  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

version = get_kb_item_or_exit("Host/Cisco/IOS/Version");

vuln     = FALSE;
override = FALSE;
  
vuln_versions = make_list(
  "15.2(2)T",
  "15.2(1)T1",
  "15.2(1)T",
  "15.2(1)GC1",
  "15.2(1)GC",
  "15.1(4)M3a",
  "15.1(4)M3",
  "15.1(4)M2",
  "15.1(4)M1",
  "15.1(4)M0b",
  "15.1(4)M0a",
  "15.1(4)M"
);

foreach ver (vuln_versions)
{
  if (ver == version)
  {
    vuln = TRUE;
    break;
  }
}

if (!vuln) audit(AUDIT_INST_VER_NOT_VULN, 'Cisco IOS', version);

bugs = make_list();

# Check for WAAS Express or MACE
if (vuln && get_kb_item("Host/local_checks_enabled"))
{
  buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config",
                              "show running-config");
  if (check_cisco_result(buf))
  {
    # WAAS Express : 2 checks for WAAS Express to distinguish it from WAAS
    if (preg(multiline:TRUE, pattern:"^(parameter|policy)-map type waas ", string:buf) &&
        preg(multiline:TRUE, pattern:"^\s*waas enable", string:buf))
      bugs = make_list("CSCtt45381");
    # MACE check
    if (preg(multiline:TRUE, pattern:"^\s*mace enable", string:buf))
      bugs = make_list(bugs, "CSCtq64987", "CSCtu57226");
  }
  else if (cisco_needs_enable(buf))
  {
    bugs     = make_list("CSCtt45381", "CSCtq64987", "CSCtu57226");
    override = TRUE;
  }
}

if (empty(bugs)) audit(AUDIT_HOST_NOT, "affected");

if (report_verbosity > 0)
{
  report =
    '\n  Cisco bug IDs     : ' + join(bugs, sep:' / ') +
    '\n  Installed release : ' + ver +
    '\n';
  security_hole(port:0, extra:report + cisco_caveat(override));
}
else security_hole(port:0, extra:cisco_caveat(override));
