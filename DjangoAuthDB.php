<?php
/**
 * Authentication plugin interface. Instantiate a subclass of AuthPlugin
 * and set $wgAuth to it to authenticate against some external tool.
 *
 * The default behavior is not to do anything, and use the local user
 * database for all authentication. A subclass can require that all
 * accounts authenticate externally, or use it only as a fallback; also
 * you can transparently create internal wiki accounts the first time
 * someone logs in who can be authenticated externally.
 *
 * This interface is a derivation of AuthJoomla and might change a bit before 1.4.0 final is done...
 *
 */
$wgExtensionCredits['parserhook'][] = array (
        'name' => 'DjangoAuthDB',
        'author' => '[http://www.mediawiki.org/wiki/User:Bilardi Alessandra Bilardi]',
        'description' => 'Authenticate users about external MySQL database',
        'url' => 'http://www.mediawiki.org/wiki/Extension:DjangoAuthDB',
        'version' => '0.1',
);
 
require_once ( 'includes/AuthPlugin.php' );
class DjangoAuthDB extends AuthPlugin
{
 
    /**
    * Add into LocalSettings.php the following code: 
    *
    * MySQL Host Name.
    * $wgDjangoAuthDB_MySQL_Host = '';
    * MySQL Username.      
    * $wgDjangoAuthDB_MySQL_Username = '';
    * MySQL Password.        
    * $wgDjangoAuthDB_MySQL_Password = '';
    * MySQL Database Name.    
    * $wgDjangoAuthDB_MySQL_Database = '';
    * MySQL Database Table of users data.
    * $wgDjangoAuthDB_MySQL_Table = '';
    * MySQL Database username column label.
    * $wgDjangoAuthDB_MySQL_Login = '';
    * MySQL Database login password column label
    * $wgDjangoAuthDB_MySQL_Pswrd = '';
    * MySQL Database email column label
    * $wgDjangoAuthDB_MySQL_Email = '';
    * MySQL Database user real name column label
    * $wgDjangoAuthDB_MySQL_RealN = '';
    * require_once("$IP/extensions/DjangoAuthDB/DjangoAuthDB.php");
    * $wgAuth = new DjangoAuthDB();
    *
    * @return Object Database
    */
    private function connectToDB()
    {
        $db = & Database :: newFromParams(
        $GLOBALS['wgDjangoAuthDB_MySQL_Host'],
        $GLOBALS['wgDjangoAuthDB_MySQL_Username'],
        $GLOBALS['wgDjangoAuthDB_MySQL_Password'],
        $GLOBALS['wgDjangoAuthDB_MySQL_Database']);
 
        $this->userTable = $GLOBALS['wgDjangoAuthDB_MySQL_Table'];
        $this->userLogin = $GLOBALS['wgDjangoAuthDB_MySQL_Login'];
        $this->userPswrd = $GLOBALS['wgDjangoAuthDB_MySQL_Pswrd'];
        $this->userEmail = $GLOBALS['wgDjangoAuthDB_MySQL_Email'];
        $this->userFirstName = $GLOBALS['wgDjangoAuthDB_MySQL_FirstName'];
        $this->userLastName = $GLOBALS['wgDjangoAuthDB_MySQL_LastName'];
        wfDebug("DjangoAuthDB::connectToDB() : DB failed to open\n");
        return $db;
    }
 
    /**
     * Check whether there exists a user account with the given name.
     * The name will be normalized to MediaWiki's requirements, so
     * you might need to munge it (for instance, for lowercase initial
     * letters).
     *
     * @param $username String: username.
     * @return bool
     * @public
     */
    function userExists( $username ) {
        # Override this!
        return true;
    }
 
    /**
     * Check if a username+password pair is a valid login.
     * The name will be normalized to MediaWiki's requirements, so
     * you might need to munge it (for instance, for lowercase initial
     * letters).
     *
     * @param $username String: username.
     * @param $password String: user password.
     * @return bool
     * @public
     */
    function authenticate( $username, $password )
    {
      $db = $this->connectToDB();
      $hash_password = $db->selectRow($this->userTable,array ($this->userPswrd), array ($this->userLogin => $username ), __METHOD__ );
      $is_active = $db->selectRow($this->userTable,array ('is_active'), array ($this->userLogin => $username ), __METHOD__ );
      $hpwa = explode("$", $hash_password->{password});
      if ( ($hpwa[2] == sha1($hpwa[1].$password)) &&
          ($is_active->{is_active} == 1) ) {
        return true;
      }
      return false;
    }

    /**
     * Set the domain this plugin is supposed to use when authenticating.
     *
     * @param $domain String: authentication domain.
     * @public
     */
    function setDomain( $domain ) {
        $this->domain = $domain;
    }

    /**
     * Check to see if the specific domain is a valid domain.
     *
     * @param $domain String: authentication domain.
     * @return bool
     * @public
     */
    function validDomain( $domain ) {
        return true;
    }

    /**
     * When a user logs in, optionally fill in preferences and such.
     * For instance, you might pull the email address or real name from the
     * external user database.
     *
     * The User object is passed by reference so it can be modified; don't
     * forget the & on your function declaration.
     *
     * @param User $user
     * @public
     */
    function updateUser( &$user )
    {
        $db = $this->connectToDB();
        $euser = $db->selectRow($this->userTable,array ( '*' ), array ($this->userLogin => $user->mName ), __METHOD__ );
        $user->setRealName($euser->{$this->userFirstName}." ".$euser->{$this->userLastName});
        $user->setEmail($euser->{$this->userEmail});
        $user->mEmailAuthenticated = wfTimestampNow();
        $user->saveSettings();
        //exit;
        # Override this and do something
        return true;
    }
    function disallowPrefsEditByUser() {
        return array (
                        'wpRealName' => true,
                        'wpUserEmail' => true,
                        'wpNick' => true
        );
    }
 
    /**
     * Return true if the wiki should create a new local account automatically
     * when asked to login a user who doesn't exist locally but does in the
     * external auth database.
     *
     * If you don't automatically create accounts, you must still create
     * accounts in some way. It's not possible to authenticate without
     * a local account.
     *
     * This is just a question, and shouldn't perform any actions.
     *
     * @return bool
     * @public
     */
    function autoCreate() {
        return true;
    }
 
    /**
     * Can users change their passwords?
     *
     * @return bool
     */
    function allowPasswordChange() {
        return false;
    }
 
    /**
     * Set the given password in the authentication database.
     * As a special case, the password may be set to null to request
     * locking the password to an unusable value, with the expectation
     * that it will be set later through a mail reset or other method.
     *
     * Return true if successful.
     *
     * @param $user User object.
     * @param $password String: password.
     * @return bool
     * @public
     */
    function setPassword( $user, $password ) {
        return true;
    }
 
    /**
     * Update user information in the external authentication database.
     * Return true if successful.
     *
     * @param $user User object.
     * @return bool
     * @public
     */
    function updateExternalDB( $user ) {
        $db = $this->connectToDB();
        $euser = $db->selectRow($this->userTable,array ( '*' ), array ($this->userLogin => $user->mName ), __METHOD__ );
        $user->setRealName($euser->{$this->userFirstName}." ".$euser->{$this->userLastName});
        $user->setEmail($euser->{$this->userEmail});
        $user->mEmailAuthenticated = wfTimestampNow();
        $user->saveSettings();
        return true;
    }
 
    /**
     * Check to see if external accounts can be created.
     * Return true if external accounts can be created.
     * @return bool
     * @public
     */
    function canCreateAccounts() {
        return false;
    }
 
    /**
     * Add a user to the external authentication database.
     * Return true if successful.
     *
     * @param User $user - only the name should be assumed valid at this point
     * @param string $password
     * @param string $email
     * @param string $realname
     * @return bool
     * @public
     */
    function addUser( $user, $password, $email='', $realname='' ) {
        return false;
    }
 
 
    /**
     * Return true to prevent logins that don't authenticate here from being
     * checked against the local database's password fields.
     *
     * This is just a question, and shouldn't perform any actions.
     *
     * @return bool
     * @public
     */
    function strict() {
        return true;
    }
 
    /**
     * When creating a user account, optionally fill in preferences and such.
     * For instance, you might pull the email address or real name from the
     * external user database.
     *
     * The User object is passed by reference so it can be modified; don't
     * forget the & on your function declaration.
     *
     * @param $user User object.
     * @param $autocreate bool True if user is being autocreated on login
     * @public
     */
    function initUser( &$user, $autocreate=false ) {
        # Override this to do something.
    }
 
    /**
     * If you want to munge the case of an account name before the final
     * check, now is your chance.
     */
    function getCanonicalName( $username ) {
        return $username;
    }
}
