#TRUSTED 6bce425b22f06bce6a084eaf9cceebe8e5ed3ec1ab8ce374fac32056b0f32d75ac76fb1c24b861527be212e9d8d3fb5000cf76970079723c60956d6dfce519126ed732faf3135b43513e952b251c2cb55a8d2fab2138a87c091ab725e015a7bc150d83b8419c2811531a12887c573dea96693840103b612768d3a1f00fe37e768309bee4e6dafef4e1c35ce1a7f2a30dc48a53fefebde54953e20c80f6c6e15a71440fba08fa97ef2baade9aefeaecb31a7b604bb37d55afcfb8d84914bae4631eb1ed487ebcdaa4f963462722ae0fd88fc6fc24b6cf57f0b1a80834559274137b75dd49d84739427b29157ed6dd674f3b448da9dc0b8f6aa5359584cf51dfe28a5f50bfccc3658db2ff030d35308f862a91a6b8dff9fa985b46d4352360afcd704bb814e0ed87c0c17151fa4af1dbf13aec5435984161813f9f7ac8b866c7ed542e5402f203bca1e4d7e3d886a373062a3cef4a263c2c50a96238d51baca7d4c3d90306c0ae2e679098dac90d2e9510473cb54246f9c2d6e92cb40203518790ba844bc6a360ea1fe76137eb546395aff229ab29395324da5e53e29c26625c9d2fd6966f12ca10479c20df56f7d41efc2dd2b649b97af6158613f9e77cd1b0c1e5a3462e360d3e775fd3b135b5ad54598a42adecac2e00692f6928b5926e81bd2767e65ff745b11c4c59e7dcae796d362fdbea1577d1cfd8ed0c9b15373045e9
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(96338);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2017/01/11");

  script_cve_id("CVE-2016-7456");
  script_bugtraq_id(94990);
  script_osvdb_id(149056);
  script_xref(name:"VMSA", value:"2015-0024");
  script_xref(name:"IAVB", value:"2017-B-0003");

  script_name(english:"VMware vSphere Data Protection Private SSH Key Authentication Bypass (VMSA-2016-0024)");
  script_summary(english:"Checks the version of VMware vSphere Data Protection.");

  script_set_attribute(attribute:"synopsis", value:
"A virtualization appliance installed on the remote host is affected by
an authentication bypass vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of VMware vSphere Data Protection installed on the remote
host is 5.5.x / 5.8.x / 6.0.x / 6.1.x. It is, therefore, affected by
an authentication bypass vulnerability due to the use of an SSH
private key that has a known password and which is configured to allow
key-based authentication. A remote attacker can exploit this to gain
root login access via an SSH session.");
  script_set_attribute(attribute:"see_also", value:"http://www.vmware.com/security/advisories/VMSA-2016-0024.html");
  # https://kb.vmware.com/selfservice/microsites/search.do?language=en_US&cmd=displayKC&externalId=2147069
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e458ec43");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/12/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/12/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/01/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:vmware:vsphere_data_protection");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/vSphere Data Protection/Version");
  script_require_ports("Services/ssh", 22);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("ssh_func.inc");

app_name = "vSphere Data Protection";
version = get_kb_item_or_exit("Host/vSphere Data Protection/Version");
port = get_service(svc:'ssh', default:22, exit_on_fail:TRUE);
vuln = FALSE;
admin = FALSE;
root = FALSE;

dpnid = "-----BEGIN DSA PRIVATE KEY-----
MIIBuwIBAAKBgQCWUMSv1kpW6ekyej2CaRNn4uX0YJ1xbzp7s0xXgevU+x5GueQS
mS+Y+DCvN7ea2MOupF9n77I2qVaLuCTZo1bUDWgHFAzc8BIRuxSa0/U9cVUxGA+u
+BkpuepaWGW4Vz5eHIbtCuffZXlRNcTDNrqDrJfKSgZW2EjBNB7vCgb1UwIVANlk
FYwGnfrXgyXiehj0V8p9Mut3AoGANktxdMoUnER7lVH1heIMq6lACWOfdbltEdwa
/Q7OeuZEY434C00AUsP2q6f9bYRCdOQUeSC5hEeqb7vgOe/3HN02GRH7sPZjfWHR
/snADZsWvz0TZQuybs8dEdGh/ezGhiItCINFkVg7NvSXx85dMVsB5N9Ju0gDsZxW
/d41VXYCgYBH0zIlb3lvioedyZj2mKF6fycnCZIeeDnL8wZtZPStRht6i4PFTCX1
Y/Ogw0L0bhuthOx+VTgICB87r0TmXElNUDLSncsxuw7pmHa669idUkv43CjeDkH0
kGFEHt4QA6/xw1Xq9oNpRJTo62ZsFmv0Pwp3uE7up8s0LW1O6fr+OwIVAKCJZ8nm
UwIdhEc9aU7sBDTFijP+
-----END DSA PRIVATE KEY-----";

dpn_pub = "ssh-dss AAAAB3NzaC1kc3MAAACBAJZQxK/WSlbp6TJ6PYJpE2fi5fRgnXFvOnuzTFeB69T7Hka55BKZL5j4MK83t5rYw66kX2fvsjapVou4JNmjVtQNaAcUDNzwEhG7FJrT9T1xVTEYD674GSm56lpYZbhXPl4chu0K599leVE1xMM2uoOsl8pKBlbYSME0Hu8KBvVTAAAAFQDZZBWMBp3614Ml4noY9FfKfTLrdwAAAIA2S3F0yhScRHuVUfWF4gyrqUAJY591uW0R3Br9Ds565kRjjfgLTQBSw/arp/1thEJ05BR5ILmER6pvu+A57/cc3TYZEfuw9mN9YdH+ycANmxa/PRNlC7Juzx0R0aH97MaGIi0Ig0WRWDs29JfHzl0xWwHk30m7SAOxnFb93jVVdgAAAIBH0zIlb3lvioedyZj2mKF6fycnCZIeeDnL8wZtZPStRht6i4PFTCX1Y/Ogw0L0bhuthOx+VTgICB87r0TmXElNUDLSncsxuw7pmHa669idUkv43CjeDkH0kGFEHt4QA6/xw1Xq9oNpRJTo62ZsFmv0Pwp3uE7up8s0LW1O6fr+Ow== dpn@dpn41s";

if (
    version =~ "^(5\.[58]|6\.[01])([^0-9]|$)"
    )
{
  sock_g = ssh_open_connection();
  if (! sock_g) audit(AUDIT_SOCK_FAIL, port);

  admin_authkeys = ssh_cmd(cmd:"cat /home/admin/.ssh/authorized_keys*");
  root_authkeys = ssh_cmd(cmd:"cat /root/.ssh/authorized_keys*");

  if(dpn_pub >< admin_authkeys) admin = TRUE;
  if(dpn_pub >< root_authkeys) root = TRUE;

  ssh_close_connection();
}

else
  audit(AUDIT_NOT_INST, app_name +" 5.5.x / 5.8.x / 6.0.x / 6.1.x ");

if (admin || root)
{
  report =
    '\nThe following users have a compromised ssh key in their authorized_keys file : \n\n';
  report +=   'Users : ';
  if(admin)
    report += '\n  - admin';
  if(root)
    report += '\n  - root';
    report +=
    '\n\nPrivate Key  : \n\n' + dpnid +
    '\n\nPublic Key   : \n' + dpn_pub + '\n';
  security_report_v4(severity:SECURITY_HOLE, port:0, extra:report);
}
else audit(AUDIT_INST_VER_NOT_VULN, app_name, version);
