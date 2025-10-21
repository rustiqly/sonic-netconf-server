////////////////////////////////////////////////////////////////////////////////
//                                                                            //
//  Copyright 2019 Broadcom. The term Broadcom refers to Broadcom Inc. and/or //
//  its subsidiaries.                                                         //
//                                                                            //
//  Licensed under the Apache License, Version 2.0 (the "License");           //
//  you may not use this file except in compliance with the License.          //
//  You may obtain a copy of the License at                                   //
//                                                                            //
//     http://www.apache.org/licenses/LICENSE-2.0                             //
//                                                                            //
//  Unless required by applicable law or agreed to in writing, software       //
//  distributed under the License is distributed on an "AS IS" BASIS,         //
//  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.  //
//  See the License for the specific language governing permissions and       //
//  limitations under the License.                                            //
//                                                                            //
////////////////////////////////////////////////////////////////////////////////

package server

import (
	"github.com/golang/glog"
	//"github.com/msteinert/pam"
	"golang.org/x/crypto/ssh"
)


func PAMAuthenAndAuthorSSH(username string, passwd string) bool {

	var rc struct{
		ID string
	}

	rc.ID = username

	glog.Infof("[%s] Received user=%s", rc.ID, username)

	/*
	 * mgmt-framework container does not have access to /etc/passwd, /etc/group,
	 * /etc/shadow and /etc/tacplus_conf files of host. One option is to share
	 * /etc of host with /etc of container. For now disable this and use ssh
	 * for authentication.
	 */
	/* err := PAMAuthUser(username, passwd)
	    if err != nil {
			log.Printf("Authentication failed. user=%s, error:%s", username, err.Error())
	        return err
	    }*/

	//Use ssh for authentication.
	config := &ssh.ClientConfig{
		User: username,
		Auth: []ssh.AuthMethod{
			ssh.Password(passwd),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}
	_, err := ssh.Dial("tcp", "127.0.0.1:22", config)
	if err != nil {
		glog.Infof("[%s] Failed to authenticate; %v", rc.ID, err)
		return false
	}

	glog.Infof("[%s] Authentication passed. user=%s ", rc.ID, username)
	return true
}




