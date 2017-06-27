#TRUSTED 1b19d48595ec0770620ad7d86b9d3bfbd40569d636e2d75f850c5b907ab551645f67bc2b26e9b3c4a106c6666f6329f2e1c85af293fbdc028f9177b418d60b9283552da06a6bac5ed94486fa5fca0b033186b39e55888cdef14f6291cdebf1fc95bbb7fe58c1b3d6998c895f2b5a2df4691c341f6ab75106ac12a44535d01508698075dd57abc7ec6e7048006f9f089d4a77223603e05fd6eaf0be17f9a07a83d04d40da338fd2e9ae65100482a6bde35d0746b49bb9ef5cb0442b40c1d1ae1c26463add14dff24aa69bebfc308d6a3dfad71a2d50820111774746ea584fbb7ba7281a578a35a59b197473a7dd805a9096f2d4582adbf2c0c81fe42f4c591afdf6a0b5a7cdacc1ef9e4212df230a8ca0fbf59611e3c7c4fb3bc329b3aa198f93ace6d41f5e7b77ffae65053ce02fdaa6ba94a53f0e648609da8e9ee74e76b7106bfdf1db77c0ef310b42e9a82e83b83cb14e954ae1c15c342ce57c69de93f3b9a771c75977fa3f38bf2efbd585a7b7d2da3aaf9d0c17e173f2221139d04adc5f8d2c925665b5d7d28d2af14304a04b4b67e36e279399350afd3069d60ffc58aad0864be622607bbd1720cdcaf9f431538eef759b6900743fdcb3b7d9abdf5ffce6c75a62d4834a6ba0bdda4974cd3411b4cea70311af4e5ef821036da1292ffb3ad42a99973e0183fdf75bfe79787804e4cb3b7771df07e99b61e8f756801e6d
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(57620);
 script_version("1.3");
 script_set_attribute(attribute:"plugin_modification_date", value:"2012/06/12");

 script_name(english:"Small SSH RSA Key");
 script_summary(english:"Negotiate SSHd connections");

 script_set_attribute(attribute:"synopsis", value:
"The SSH server is running on the remote host has an overly small
public key.");
 script_set_attribute(attribute:"description", value:
"The remote SSH daemon has a small key size, which is insecure.  Given
current technology, it should be 768 bits at a minimum.");
 script_set_attribute(attribute:"solution", value:"Generate a new, larger key for the service.");
 script_set_attribute(attribute:"risk_factor", value:"High");

 script_set_attribute(attribute:"plugin_publication_date", value:"2012/01/25");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2012 Tenable Network Security, Inc.");
 script_family(english:"General");

 script_dependencie("ssh_detect.nasl");
 script_require_ports("Services/ssh", 22);
 script_exclude_keys("global_settings/supplied_logins_only");
 exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("ssh_func.inc");


if (supplied_logins_only) audit(AUDIT_SUPPLIED_LOGINS_ONLY);


port = get_service(svc:"ssh", default:22, exit_on_fail:TRUE);

soc = open_sock_tcp(port);
if (!soc) audit(AUDIT_SOCK_FAIL, port);

_ssh_socket = soc;

ssh_login(login:"n3ssus", password:rand_str(length:8));

if ( KEY_LEN > 0 && KEY_LEN < 768 ) security_hole(port:port, extra:'The remote SSH key size is set to ' + KEY_LEN + 'bits');

