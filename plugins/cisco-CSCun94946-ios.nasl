#TRUSTED aa9291ca595256d46db82c75295976cade5ae9677c67e953bfef2de5cf7d61ce31c5e9f1d3cc607dcf09978ed3b8b24476a52056c4e5da8a22dd871655916fc1d3353b3e658b900958be89f9ee975c3ee11ca1245cf67142183caef9fdc0b4bb51562c10f74bab8b8d28db2c23e1fd3adce82debe2edbcaf57d90cae56757fee1ec96c8916bc779bb076bcbeb8687929433a3295816dbedc2bc79b927364c3787f60b931292f56cdee0a28d4ea2e76c37712a5076c26b332cd354cd80b03c39084bc12e0b11dc280501a47a55bd45337a2c7e1d591b0fd2e4d401405778bbd3dfe949aa71f24cfcaefa041d3d21745cdea84588e1f1e5787c83b53ac4ddd9536cfd62ef62ef92c160c36d055df2d50333c485c2b89cee3597c8aad54e8935e9afea1d3eb3d206872367c09ab7393cbd8c9f90441ec8b85efd45b4c58883c404cbeedec8e87f3e2b63600397a628b868e7a6dedf14b0ebca8e76a93e16de84d3d5bcf8d5d293ccb3278e9863346bc30773c16b140d7bdb4d069a7f65b021e1614bfde122d1951a6a881da60e30aebef77db30e20e78de279a1098f20fa1f30aaf7d72366de88a165d7e41984fa9e447d84a9b87d77419ba790950df336792b0edae0e40192abe5b239b8cf3bc5a60d2453977700b3d9eec13ca77569c163dc8b6c70f3c0cf5562d6cdc9687bcf842a2523d227d92b5b88995e0b76320f810d16d
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(91854);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2016/06/27");

  script_cve_id("CVE-2014-2146");
  script_osvdb_id(138980);
  script_xref(name:"CISCO-BUG-ID", value:"CSCun94946");

  script_name(english:"Cisco IOS Zone-Based Firewall Feature Security Bypass (CSCun94946)");
  script_summary(english:"Checks the IOS version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Cisco IOS software running
on the remote device is affected by a security bypass vulnerability
in the Zone-Based Firewall feature due to insufficient zone checking
for traffic belonging to existing sessions. An unauthenticated, remote
attacker can exploit this, by injecting spoofed traffic that matches
existing connections, to bypass security access restrictions on the
device and gain access to resources.");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCun94946");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/security/center/viewAlert.x?alertId=39129");
  # http://www.cisco.com/c/en/us/td/docs/ios/15_5m_and_t/release/notes/15_5m_and_t/155-3MCAVS.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6e66b42d");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant patch referenced in the Cisco security advisory.
Alternatively, disable the Zone-Based Firewall feature according to
the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/05/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/05/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/06/27");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("cisco_ios_version.nasl");
  script_require_keys("Host/Cisco/IOS/Version");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

ver = get_kb_item_or_exit("Host/Cisco/IOS/Version");

flag = 0;
override = 0;
fix_ver_s = "15.5(2)S";
fix_ver_t = "15.5(2)T";

if (cisco_gen_ver_compare(a:ver, b:fix_ver_s) < 0) flag++;
else if (cisco_gen_ver_compare(a:ver, b:fix_ver_t) < 0) flag++;

if (flag > 0 && get_kb_item("Host/local_checks_enabled"))
{
  flag = 0;
  # verify zone-based firewall is enabled
  buf = cisco_command_kb_item("Host/Cisco/Config/show_zone_security", "show zone security");
  if (check_cisco_result(buf))
  {
    if (preg(pattern:"Member Interfaces:", multiline:TRUE, string:buf))
      flag = 1;
  }
  else if (cisco_needs_enable(buf)) { flag = 1; override = 1; }
}

if (flag > 0)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Cisco bug ID      : CSCun94946' +
      '\n  Installed release : ' + ver +
      '\n  Fix releases      : See solution.' +
      '\n';
    security_warning(port:0, extra:report + cisco_caveat(override));
  }
  else security_warning(port:0, extra:cisco_caveat(override));
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
