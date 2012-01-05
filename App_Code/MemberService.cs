using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Web;
using System.Web.Services;
using System.Web.Script.Services;
using System.Xml;

/// <summary>
/// External authentication service example.
/// </summary>
[WebService(Namespace = "http://www.regonline.com/api")]
[WebServiceBinding(ConformsTo = WsiProfiles.BasicProfile1_1)]
// To allow this Web Service to be called from script, using ASP.NET AJAX, uncomment the following line. 
// [System.Web.Script.Services.ScriptService]
public class MemberService : System.Web.Services.WebService
{
    #region authresponse class

    /// <summary>
    /// Class representing authentication response
    /// </summary>
    public class authresponse
    {
        public Boolean success { get; set; }
        public string errormessage { get; set; }
        public string prefix { get; set; }
        public string firstname { get; set; }
        public string middlename { get; set; }
        public string lastname { get; set; }
        public string suffix { get; set; }
        public string jobtitle { get; set; }
        public string company { get; set; }
        public string address1 { get; set; }
        public string address2 { get; set; }
        public string city { get; set; }
        public string state { get; set; }
        public string postalcode { get; set; }
        public string workphone { get; set; }
        public string homephone { get; set; }
        public string country { get; set; }
        public string extension { get; set; }
        public string fax { get; set; }
        public string mobilephone { get; set; }
        public string emergencycontactphone { get; set; }
        public string dob { get; set; }
        public string gender { get; set; }
        public string secondaryemail { get; set; }
    }

    #endregion

    #region public methods

    /// <summary>
    /// Member Authentication by user name
    /// Example: http://localhost/MemberService.asmx/ValidateMemberByUserName?eventID=0&regtypeID=0&regtypeName=&username=testUserName&eventlang=
    /// </summary>
    /// <param name="username"></param>
    /// <returns></returns>
    [WebMethod]
    [ScriptMethod(UseHttpGet = true, ResponseFormat = ResponseFormat.Xml)]
    [return: System.Xml.Serialization.XmlElementAttribute("authresponse")]
    public authresponse ValidateMemberByUserName(
        int eventid,
        int regtypeid,
        string regtypename,
        string username,
        string eventlang)
    {
        return ValidateXAuthCredentials(string.Empty, username, string.Empty, false);
    }

    /// <summary>
    /// Member Authentication by user name and hashed password
    /// Example: http://localhost/MemberService.asmx/ValidateMemberByUserNamePassword?eventid=506257&regtypeid=73482&regtypename=xAuthUserID&username=111111&eventlang=en-AU&hashedpassword=fd5cb51bafd60f6fdbedde6e62c473da6f247db271633e15919bab78a02ee9eb
    /// </summary>
    [WebMethod]
    [ScriptMethod(UseHttpGet = true, ResponseFormat = ResponseFormat.Xml)]
    [return: System.Xml.Serialization.XmlElementAttribute("authresponse")]
    public authresponse ValidateMemberByUserNamePassword(
        int eventid,
        int regtypeid,
        string regtypename,
        string username,
        string hashedPassword,
        string eventlang)
    {
        return ValidateXAuthCredentials(string.Empty, username, hashedPassword, true);
    }

    /// <summary>
    /// Member Authentication by email and hashed password
    /// Example: http://localhost/MemberService.asmx/ValidateMemberByEmailPassword?eventid=506257&regtypeid=73482&regtypename=xAuthUserID&username=user123&eventlang=en-AU&hashedpassword=fd5cb51bafd60f6fdbedde6e62c473da6f247db271633e15919bab78a02ee9eb&email=qa@tester.com
    /// </summary>
    /// <returns></returns>
    [WebMethod]
    [ScriptMethod(UseHttpGet = true, ResponseFormat = ResponseFormat.Xml)]
    [return: System.Xml.Serialization.XmlElementAttribute("authresponse")]
    public authresponse ValidateMemberByEmailPassword(
        int eventid,
        int regtypeid,
        string regtypename,
        string email,
        string username,
        string hashedPassword,
        string eventlang)
    {
        return ValidateXAuthCredentials(email, string.Empty, hashedPassword, true);
    }

    /// <summary>
    /// Member Authentication by email and user name
    /// Example: http://localhost/MemberService.asmx/ValidateMemberByEmailUserName?eventid=506257&regtypeid=73482&regtypename=xAuthUserID&eventlang=en-AU&email=just@name.com&username=ivan
    /// </summary>
    /// <returns></returns>
    [WebMethod]
    [ScriptMethod(UseHttpGet = true, ResponseFormat = ResponseFormat.Xml)]
    [return: System.Xml.Serialization.XmlElementAttribute("authresponse")]
    public authresponse ValidateMemberByEmailUserName(
        int eventid,
        int regtypeid,
        string regtypename,
        string email,
        string username,
        string eventlang)
    {
        return ValidateXAuthCredentials(email, username, string.Empty, false);
    }

    /// <summary>
    /// Member Authentication by email
    /// Example: http://localhost/MemberService.asmx/ValidateMemberByEmail?eventid=506257&regtypeid=73482&regtypename=xAuthUserID&eventlang=en-AU&email=just@name.com
    /// </summary>
    /// <returns></returns>
    [WebMethod]
    [ScriptMethod(UseHttpGet = true, ResponseFormat = ResponseFormat.Xml)]
    [return: System.Xml.Serialization.XmlElementAttribute("authresponse")]
    public authresponse ValidateMemberByEmail(
        int eventid,
        int regtypeid,
        string regtypename,
        string email,
        string eventlang)
    {
        return ValidateXAuthCredentials(email, string.Empty, string.Empty, false);
    }

    #endregion

    #region private methods

    /// <summary>
    /// Validate external authentication credentials
    /// </summary>
    /// <param name="email">Email Address</param>
    /// <param name="username">Membership number, user name or ID</param>
    /// <param name="passwordHash">SHA-256 hashed password</param>
    /// <returns></returns>
    private authresponse ValidateXAuthCredentials(string email, string username, string passwordHash, bool validatePassword)
    {
        // validate parameters
        if (string.IsNullOrEmpty(email) && string.IsNullOrEmpty(username) && string.IsNullOrEmpty(passwordHash))
        {
            return GetErrorResponse("Authentication parameters are empty.");
        }

        // load list of members
        XmlDocument members = LoadMembersList();
        if (members.ChildNodes.Count <= 0)
        {
            return GetErrorResponse("Membership database loading failure.");
        }

        // build search criteria
        string searchAttributes = BuildSearchCriteria(email, username);

        // find matching members
        XmlNodeList matchingMembers = members.SelectNodes(string.Format("//members/member[{0}]", searchAttributes));
        XmlNode matchingMember = matchingMembers.Count > 0 ? matchingMembers[0] : null;

        // verify password
        if (matchingMember != null && validatePassword
            && !IsValidPassword(matchingMember.Attributes["password"].Value, passwordHash))
        {
            matchingMember = null;
        }

        // build the response
        return matchingMember != null ? GetSuccessResponse(matchingMember) :
            GetErrorResponse("Authentication failure. Please try again.");
    }

    /// <summary>
    /// password validation
    /// </summary>
    private bool IsValidPassword(string databasePassword, string passedPasswordHash)
    {
        return ComputeHash(databasePassword) == passedPasswordHash;
    }

    /// <summary>
    /// Generate the SHA256 hash from a passed string value
    /// </summary>
    public static string ComputeHash(string stringValue)
    {
        SHA256Managed shaM = new SHA256Managed();

        System.Text.ASCIIEncoding enc = new System.Text.ASCIIEncoding();
        string correctPasswordHash = BitConverter.ToString(shaM.ComputeHash(enc.GetBytes(stringValue)));

        // hash value cleanup
        correctPasswordHash = correctPasswordHash.Replace("-", string.Empty).ToLower();

        return correctPasswordHash;
    }

    private static string BuildSearchCriteria(string email, string username)
    {
        string searchAttributes = string.Empty;
        if (!string.IsNullOrEmpty(email))
        {
            searchAttributes += !string.IsNullOrEmpty(searchAttributes) ? " and " : string.Empty;
            searchAttributes += string.Format("@email='{0}'", email);
        }

        if (!string.IsNullOrEmpty(username))
        {
            searchAttributes += !string.IsNullOrEmpty(searchAttributes) ? " and " : string.Empty;
            searchAttributes += string.Format("@username='{0}'", username);
        }

        return searchAttributes;
    }

    private XmlDocument LoadMembersList()
    {
        XmlDocument members = new XmlDocument();
        string path = Server.MapPath("~/App_Data/XAuthTestData.xml");
        members.Load(path);
        return members;
    }

    /// <summary>
    /// Build successful authentication response
    /// </summary>
    /// <param name="xmlNode"></param>
    /// <returns></returns>
    private authresponse GetSuccessResponse(XmlNode xmlNode)
    {
        MemberService.authresponse authResponse = new MemberService.authresponse();
        authResponse.success = true;
        authResponse.errormessage = string.Empty;
        authResponse.firstname = xmlNode.SelectSingleNode("firstname").InnerText;
        authResponse.lastname = xmlNode.SelectSingleNode("lastname").InnerText;
        authResponse.middlename = xmlNode.SelectSingleNode("middlename").InnerText;
        authResponse.suffix = xmlNode.SelectSingleNode("suffix").InnerText;
        authResponse.jobtitle = xmlNode.SelectSingleNode("jobtitle").InnerText;
        authResponse.company = xmlNode.SelectSingleNode("company").InnerText;
        authResponse.address1 = xmlNode.SelectSingleNode("address1").InnerText;
        authResponse.address2 = xmlNode.SelectSingleNode("address2").InnerText;
        authResponse.city = xmlNode.SelectSingleNode("city").InnerText;
        authResponse.state = xmlNode.SelectSingleNode("state").InnerText;
        authResponse.postalcode = xmlNode.SelectSingleNode("postalcode").InnerText;
        authResponse.workphone = xmlNode.SelectSingleNode("workphone").InnerText;
        authResponse.homephone = xmlNode.SelectSingleNode("homephone").InnerText;
        authResponse.country = xmlNode.SelectSingleNode("country").InnerText;
        authResponse.extension = xmlNode.SelectSingleNode("extension").InnerText;
        authResponse.fax = xmlNode.SelectSingleNode("fax").InnerText;
        authResponse.mobilephone = xmlNode.SelectSingleNode("mobilephone").InnerText;
        authResponse.emergencycontactphone = xmlNode.SelectSingleNode("emergencycontactphone").InnerText;
        authResponse.dob = xmlNode.SelectSingleNode("dob").InnerText;
        authResponse.gender = xmlNode.SelectSingleNode("gender").InnerText;
        authResponse.secondaryemail = xmlNode.SelectSingleNode("secondaryemail").InnerText;

        return authResponse;
    }

    /// <summary>
    /// Build unsuccessful authentication response
    /// </summary>
    private authresponse GetErrorResponse(string errorMessage)
    {
        MemberService.authresponse authresponse = new MemberService.authresponse();
        authresponse.success = false;
        authresponse.errormessage = errorMessage;

        return authresponse;
    }

    #endregion
}
