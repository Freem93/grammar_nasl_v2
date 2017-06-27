#TRUSTED 02cf4b8ab0f61f78b5e1b202ee9042e550048bf86bee82802ea70e69089624f2da47f180d1c93c84bb4f5c357f9a0a9f3d54513e59ee8848d122e15b7da641fbf1d95af34e96881927320586d1fb02312edd31f6ca412a9b67dc756af9e3d090e8942b0ed9eb4ada346c27c2d273c91f45864e933b85e744621b2196319aeaf554fed84947b3942782fa96cd5d544351e799dcec39a70d7c337592bbb5d427d028842fc3a35fbcce52ee6c218fa30f1562e2286c03a4ae87980da354efbea5dd4b18ceb8a783eb965ff46b746c49133cbe306bf7836b397074f9f98f9cf078f7257002ef33b020394c78fa35c27be8c49b71b82249471e4ad57b3313d8fbd7800d069a8aa3b355cc01885319dfdbd73361012e13480c14cacd3742569450780a3c520d3d060624950f66afdbe8b825d6444229b354ee71e8fe1674e1cdba436325bc66b7d24e4fb8dc2fc37e8fce06cc065d88607d79ef243c508bb25e1dd40d64b3ee483a1530a2ffbc918c86cc4e4efec79e97807da969b99cf48cc80f9eab540a1b884f649a8d515b3d71b215a00bc86cd57963de85926b0f862bc11af296956e555f5c607a191b541d19e007fe66184eafd84b931608dc6ba6370dae663a89c9fd90012ffc879af9d62bf3c7ceb43787d46187f6f4514ff1f2d66ab74cd242250cfa020bd5468fdb80cc06f6e966132a56a9e11816b0fb89c8c0d1fb54bb
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(69420);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2016/11/17");

  script_cve_id("CVE-2008-1369");
  script_osvdb_id(43547);
  script_xref(name:"IAVA", value:"2008-A-0025");

  script_name(english:"Sun SPARC Enterprise T5120 and T5220 Default Configuration Root Command Execution");
  script_summary(english:"Check for the configuration of the SPARC Enterprise Image");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Solaris host has a misconfigured SSH server."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote Sun SPARC Enterprise Server has been mistakenly shipped with
factory settings in the pre-installed Solaris 10 image which configures
the remote SSH server insecurely. As a result, local or remote users may
leverage these misconfigurations to execute arbitrary commands with the
privileges of the root (uid 0) user."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://download.oracle.com/sunalerts/1018965.1.html"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Follow the steps in the workaround section of the advisory above"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cwe_id(264);

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:sun:solaris");

  script_set_attribute(attribute:"vuln_publication_date", value:"2008/03/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2008/03/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/08/21");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");
  script_family(english:"Gain a shell remotely");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/uname");

  exit(0);
}

include("ssh_func.inc");
include("audit.inc");
include("misc_func.inc");

uname = get_kb_item_or_exit("Host/uname");
if ( "SunOS" >!< uname ) audit(AUDIT_OS_NOT, "Solaris");

ret = ssh_open_connection();
if (! ret ) audit(AUDIT_SVC_FAIL, "SSH", kb_ssh_transport());


#
# http://download.oracle.com/sunalerts/1018965.1.html
#

rep = '/etc/default/login contains:\n';
rep += buf = ssh_cmd(cmd:"grep CONSOLE= /etc/default/login");
if ( isnull(buf) ) audit(AUDIT_SVC_FAIL, "SSH", kb_ssh_transport());
if ( "#CONSOLE=/dev/console" >!< buf ) audit(AUDIT_HOST_NOT, "affected");

rep += '\n/etc/ssh/sshd_config contains:\n';
rep += buf = ssh_cmd(cmd:"grep PermitRootLogin /etc/ssh/sshd_config");
if ( isnull(buf) ) audit(AUDIT_SVC_FAIL, "SSH", kb_ssh_transport());
if ("PermitRootLogin yes" >!< buf ) audit(AUDIT_HOST_NOT, "affected");


rep += '\n/.profile contains:\n';
rep += buf = ssh_cmd(cmd:"egrep 'PS1|LOGDIR' /.profile");
if ( isnull(buf) ) audit(AUDIT_SVC_FAIL, "SSH", kb_ssh_transport());
if ( "PS1='ROOT>'" >!< buf ||
     "LOGDIR='/export/home/utslog'" >!< buf ) audit(AUDIT_HOST_NOT, "affected");

security_hole(port:kb_ssh_transport(), extra:rep);

