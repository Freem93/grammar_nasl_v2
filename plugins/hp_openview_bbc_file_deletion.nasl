#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(70171);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2014/10/24 15:51:07 $");

  script_cve_id("CVE-2011-2608");
  script_bugtraq_id(48481);
  script_osvdb_id(73502);
  script_xref(name:"HP", value:"HPSBMU02691");
  script_xref(name:"HP", value:"SSRT100483");
  script_xref(name:"HP", value:"emr_na-c02941034");

  script_name(english:"HP OpenView Communication Broker Arbitrary File Deletion (HPSBMU02691)");
  script_summary(english:"Checks version of HP OpenView Communication Broker service");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server has an arbitrary file deletion vulnerability." );
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the version of the HP OpenView
Communication Broker service running on the remote host has a
vulnerability that could allow an unauthenticated attacker to delete
arbitrary files on the system.  Successful exploits will result in a
denial of service condition or the corruption of applications running on
the affected system. 

Note that the Communication Broker can be found in various HP products
such as HP Operations Agent, HP OpenView Performance Agent, and HP
SiteScope."
  );
  script_set_attribute(attribute:"see_also", value:"http://aluigi.altervista.org/adv/ovbbccb_1-adv.txt");
  # http://h20000.www2.hp.com/bizsupport/TechSupport/Document.jsp?objectID=c02941034
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ebf8f8f8");
  script_set_attribute(
    attribute:"solution",
    value:
"Apply the relevant update referenced in HP Security Bulletin
HPSBMU02691."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/07/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/07/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/09/27");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:hp:openview");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");
  script_copyright(english:"This script is Copyright (C) 2013-2014 Tenable Network Security, Inc.");

  script_dependencies("hp_openview_bbc.nasl");
  script_require_keys("Services/ovbbc","Settings/ParanoidReport");
  script_require_ports(383);

  exit(0);
}

include('audit.inc');
include('global_settings.inc');
include('misc_func.inc');
include('http.inc');


# - The Communication Broker (ovbbccb.exe) is part of HP Operations Agent and Performance Agent
# - The advisory isn't clear on what versions of the Communication Broker are vulnerable or fixed
if (report_paranoia < 2) audit(AUDIT_PARANOID);

# Get service port
port = get_service(svc:'ovbbc',default:383, exit_on_fail:TRUE);

# Get version
ver = get_kb_item_or_exit('HP/ovbbc/' + port +'/version');

# 11.01.003 seems to be the fixed version for following reasons:
#
# 1) The advisory mentions 11.01.003 for fixes for Operations Agent 11.x. This may indicate the fixed version of the
#    Communication Broker (ovbbccd.exe) is also 11.01.003.
# 2) This fixed version is in sync with what PoC author's website (http://aluigi.altervista.org/adv/ovbbccb_1-adv.txt)
#    says about the vulnerable versions (ovbbccb.exe <= 11.0.43.0).
# 3) A patched ovbbccb.exe 11.02.009 (confirmed with the PoC) was built on October, 2011,
#    whereas the bug was discovered/disclosed around June/July 2011.
# 4) The advisory mentions "Lcore_06.21.501" for fixes for Operations Agent 8.x, the version of Communication Broker that
#    comes with HP SiteScope 11.20 is exactly 06.21.501, but it's vulnerable (confirmed with PoC).
#    So ovbbccd.exe 06.21.501 couldn't be a fixed version.
fixed = '11.01.003';

if (ver_compare(ver:ver, fix:fixed, strict:FALSE) < 0)
{
  report = NULL;
  if (report_verbosity > 0)
  {
    report =
      '\n  Installed version : ' + ver +
      '\n  Fixed version     : ' + fixed + '\n';
  }
  security_warning(port:port, extra:report);
}
else audit(AUDIT_INST_VER_NOT_VULN, 'HP OpenView Communication Broker', ver);
