import { Injectable } from '@nestjs/common'
import * as AWS from "aws-sdk"

@Injectable()
export class AppService {
  async googleLogin(req) {
    if (!req.user) {
      return 'No user from google'
    }

    if (req.user.email.split('@')[1] !== process.env.ALLOWED_DOMAIN){
      return 'Invalid permissions'
    }    


    const clientIp = req.headers['x-forwarded-for'] || req.socket.remoteAddress
    const port = parseInt(process.env.ALLOWED_PORT)
    const securityGroupId = process.env.SECURITY_GROUP_ID

    AWS.config.update({ region: 'eu-west-1' })
    const ec2 = new AWS.EC2()
    const rules = (
      await ec2
        .describeSecurityGroupRules({
          Filters: [
            {
              Name: 'group-id',
              Values: [securityGroupId],
            },
          ],
        })
        .promise()
    ).SecurityGroupRules

    // Find all rules for specific email
    const oldRuleIds = rules
      .filter(rule => rule.IsEgress == false)
      .filter(rule => rule.ToPort == port)
      .filter(rule => rule.Description == req.user.email)
      .map(rule => rule.SecurityGroupRuleId)

    if (oldRuleIds.length) {
      // Revoke old rules for specific email
      await ec2
        .revokeSecurityGroupIngress({
          GroupId: securityGroupId,
          SecurityGroupRuleIds: oldRuleIds,
        })
        .promise()
    }

    // Create new entry for email source ip
    await ec2
      .authorizeSecurityGroupIngress({
        GroupId: securityGroupId,
        IpPermissions: [
          {
            FromPort: port,
            ToPort: port,
            IpProtocol: 'tcp',
            IpRanges: [
              {
                CidrIp: `${clientIp}/32`,
                Description: req.user.email,
              },
            ],
          },
        ],
      })
      .promise()

    return `
<html>\n
  <head>\n
  </head>\n
  <body>\n
    Hello ${req.user.firstName} ${req.user.lastName}! <br/>\n
    Opening firewall for <br/>\n
    <table>\n
      <tr><th>IP</th><th>Email</th></tr>\n
      <tr><td>${clientIp}</td><td>${req.user.email}</td></tr>\n
    </table>\n
  </body>\n
</html>\n        
`
  }
}
