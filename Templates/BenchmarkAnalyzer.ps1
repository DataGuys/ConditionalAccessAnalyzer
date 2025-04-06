function Test-CASecurityBenchmark {
    <#
    .SYNOPSIS
        Evaluates Conditional Access policies against industry security benchmarks.
    .DESCRIPTION
        Assesses Conditional Access configurations against multiple security frameworks
        including NIST SP 800-53, CIS Controls, Microsoft MCRA, and ISO 27001.
        Provides detailed compliance gaps and recommendations.
    .PARAMETER BenchmarkName
        The name of the security benchmark to evaluate against.
        Valid values include: NIST, CIS, MCRA, ISO27001, PCI, HIPAA, All
    .PARAMETER Results
        The compliance check results to evaluate. If not specified, Invoke-CAComplianceCheck is run.
    .PARAMETER IncludeDetails
        If specified, includes detailed control mappings and evaluations.
    .PARAMETER OutputPath
        If specified, saves the benchmark report to the specified path.
    .EXAMPLE
        Test-CASecurityBenchmark -BenchmarkName NIST
        Evaluates the current Conditional Access configuration against NIST SP 800-53.
    .EXAMPLE
        Test-CASecurityBenchmark -BenchmarkName All -IncludeDetails -OutputPath "C:\Reports\Benchmark.html"
        Evaluates against all benchmarks with detailed results saved to an HTML file.
    .NOTES
        The benchmark evaluations are based on industry best practices and regulatory requirements.
        This assessment provides guidance but does not guarantee regulatory compliance.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet('NIST', 'CIS', 'MCRA', 'ISO27001', 'PCI', 'HIPAA', 'All')]
        [string]$BenchmarkName,
        
        [Parameter(Mandatory = $false)]
        [PSCustomObject]$Results,
        
        [Parameter(Mandatory = $false)]
        [switch]$IncludeDetails,
        
        [Parameter(Mandatory = $false)]
        [string]$OutputPath
    )
    
    begin {
        # Verify connection
        if (-not (Test-CAAnalyzerConnection)) {
            throw "Not connected to Microsoft Graph. Use Connect-CAAnalyzer first."
        }
        
        # If no results provided, run the compliance check
        if (-not $Results) {
            Write-Host "No results provided. Running comprehensive Conditional Access compliance check..." -ForegroundColor Yellow
            $Results = Invoke-CAComplianceCheck
        }
        
        # Benchmark control definitions
        $benchmarkControls = @{
            # NIST SP 800-53 Controls
            'NIST' = @(
                @{
                    Control = "AC-2"
                    Title = "Account Management"
                    Description = "Organization manages information system accounts, including establishing, activating, modifying, reviewing, disabling, and removing accounts."
                    Requirements = @(
                        @{
                            ID = "AC-2.1"
                            Description = "Conditional Access policies for privileged account management"
                            Evaluator = { param($Results) $Results.Checks.AdminMFA.AdminMFARequired }
                            Impact = "Critical"
                            Recommendation = "Implement MFA requirements for all privileged accounts"
                        },
                        @{
                            ID = "AC-2.7"
                            Description = "Role-based access schemes"
                            Evaluator = { param($Results) $Results.Checks.AdminMFA.AdminMFAPolicies.Count -gt 0 }
                            Impact = "High"
                            Recommendation = "Create role-specific Conditional Access policies"
                        }
                    )
                },
                @{
                    Control = "AC-7"
                    Title = "Unsuccessful Logon Attempts"
                    Description = "Organization enforces limit of consecutive invalid logon attempts during a specified time period."
                    Requirements = @(
                        @{
                            ID = "AC-7.1"
                            Description = "Risk-based authentication controls"
                            Evaluator = { param($Results) $Results.Checks.RiskPolicies.SignInRiskPoliciesConfigured }
                            Impact = "High"
                            Recommendation = "Deploy sign-in risk policies to detect and respond to suspicious authentication attempts"
                        }
                    )
                },
                @{
                    Control = "AC-11"
                    Title = "Session Termination"
                    Description = "Organization terminates a user session after a defined time-period of inactivity."
                    Requirements = @(
                        @{
                            ID = "AC-11.1"
                            Description = "Session timeout configuration"
                            Evaluator = { param($Results) $Results.Checks.TokenBinding.TokenSessionBindingConfigured }
                            Impact = "Medium"
                            Recommendation = "Configure token session binding with appropriate sign-in frequency"
                        }
                    )
                },
                @{
                    Control = "IA-2"
                    Title = "Identification and Authentication"
                    Description = "Organization uniquely identifies and authenticates users and devices."
                    Requirements = @(
                        @{
                            ID = "IA-2.1"
                            Description = "Multi-factor authentication for all users"
                            Evaluator = { param($Results) $Results.Checks.UserMFA.BroadUserMFARequired }
                            Impact = "Critical"
                            Recommendation = "Implement MFA for all users accessing organizational resources"
                        },
                        @{
                            ID = "IA-2.2"
                            Description = "Multi-factor authentication for privileged accounts"
                            Evaluator = { param($Results) $Results.Checks.AdminMFA.AdminMFARequired }
                            Impact = "Critical"
                            Recommendation = "Implement MFA for all privileged accounts"
                        },
                        @{
                            ID = "IA-2.6"
                            Description = "Device authentication"
                            Evaluator = { param($Results) $Results.Checks.DeviceCompliance.BroadDeviceComplianceRequired }
                            Impact = "High"
                            Recommendation = "Configure device-based Conditional Access policies"
                        },
                        @{
                            ID = "IA-2.8"
                            Description = "Access to privileged accounts across organization networks"
                            Evaluator = { param($Results) $Results.Checks.AdminMFA.AdminMFARequired -and $Results.Checks.ZeroTrust.MDCAIntegrated }
                            Impact = "High"
                            Recommendation = "Configure network access controls for privileged accounts"
                        }
                    )
                },
                @{
                    Control = "IA-5"
                    Title = "Authenticator Management"
                    Description = "Management of authenticators including verification of identity, strength of mechanism, and requirements for periodic change."
                    Requirements = @(
                        @{
                            ID = "IA-5.1"
                            Description = "Password-based authentication"
                            Evaluator = { param($Results) $Results.Checks.UserMFA.BroadUserMFARequired -or $Results.Checks.RiskPolicies.UserRiskPoliciesConfigured }
                            Impact = "High"
                            Recommendation = "Implement MFA and risk-based authentication"
                        },
                        @{
                            ID = "IA-5.3"
                            Description = "Group authenticator management"
                            Evaluator = { param($Results) 
                                $Results.Checks.AdminMFA.AdminMFARequired -and $Results.Checks.UserMFA.BroadUserMFARequired
                            }
                            Impact = "Medium"
                            Recommendation = "Configure different authentication requirements for different user groups"
                        }
                    )
                },
                @{
                    Control = "SC-7"
                    Title = "Boundary Protection"
                    Description = "Organization implements boundary protection mechanisms to control communications at external and internal boundaries."
                    Requirements = @(
                        @{
                            ID = "SC-7.1"
                            Description = "Network access control"
                            Evaluator = { param($Results) $Results.Checks.ZeroTrust.MDCAIntegrated -or $Results.Checks.ZeroTrust.GlobalSecureAccessConfigured }
                            Impact = "High"
                            Recommendation = "Configure network access controls and Cloud App Security integration"
                        }
                    )
                },
                @{
                    Control = "SC-8"
                    Title = "Transmission Confidentiality and Integrity"
                    Description = "Organization protects the confidentiality and integrity of information during transmission."
                    Requirements = @(
                        @{
                            ID = "SC-8.1"
                            Description = "Mobile data protection"
                            Evaluator = { param($Results) $Results.Checks.MAMPolicies.MAMPoliciesConfigured }
                            Impact = "High"
                            Recommendation = "Configure Mobile Application Management policies"
                        }
                    )
                },
                @{
                    Control = "SI-4"
                    Title = "Information System Monitoring"
                    Description = "Organization monitors the information system to detect attacks, unauthorized activities, and improper usage."
                    Requirements = @(
                        @{
                            ID = "SI-4.1"
                            Description = "Risk detection monitoring"
                            Evaluator = { param($Results) 
                                $Results.Checks.RiskPolicies.SignInRiskPoliciesConfigured -and 
                                $Results.Checks.RiskPolicies.UserRiskPoliciesConfigured
                            }
                            Impact = "Critical"
                            Recommendation = "Implement both sign-in risk and user risk policies"
                        },
                        @{
                            ID = "SI-4.24"
                            Description = "Indicators of compromise"
                            Evaluator = { param($Results) $Results.Checks.ZeroTrust.MDCAIntegrated }
                            Impact = "High"
                            Recommendation = "Configure Microsoft Defender for Cloud Apps integration"
                        }
                    )
                }
            ),
            # CIS Controls
            'CIS' = @(
                @{
                    Control = "5"
                    Title = "Account Management"
                    Description = "Use processes and tools to assign and manage authorization to credentials for user accounts, including administrator accounts, and service accounts."
                    Requirements = @(
                        @{
                            ID = "5.3"
                            Description = "Multi-factor Authentication for All Administrative Access"
                            Evaluator = { param($Results) $Results.Checks.AdminMFA.AdminMFARequired }
                            Impact = "Critical"
                            Recommendation = "Implement MFA requirements for all administrative users"
                        }
                    )
                },
                @{
                    Control = "6"
                    Title = "Access Control Management"
                    Description = "Use processes and tools to create, assign, manage, and revoke access credentials and privileges."
                    Requirements = @(
                        @{
                            ID = "6.5"
                            Description = "Multi-factor Authentication for All Users"
                            Evaluator = { param($Results) $Results.Checks.UserMFA.BroadUserMFARequired }
                            Impact = "Critical"
                            Recommendation = "Implement MFA requirements for all users"
                        },
                        @{
                            ID = "6.8"
                            Description = "Define and Maintain Role-Based Access Control"
                            Evaluator = { param($Results) 
                                ($Results.Checks.AdminMFA.AdminMFAPolicies | Where-Object { $_.TargetedRoles -ne "All Users" }).Count -gt 0
                            }
                            Impact = "High"
                            Recommendation = "Implement role-specific Conditional Access policies"
                        }
                    )
                },
                @{
                    Control = "10"
                    Title = "Malware Defenses"
                    Description = "Prevent or control the installation, spread, and execution of malicious applications, code, or scripts."
                    Requirements = @(
                        @{
                            ID = "10.5"
                            Description = "Enable Anti-Exploitation Features"
                            Evaluator = { param($Results) $Results.Checks.DeviceCompliance.BroadDeviceComplianceRequired }
                            Impact = "High"
                            Recommendation = "Implement device compliance requirements"
                        }
                    )
                },
                @{
                    Control = "13"
                    Title = "Network Monitoring and Defense"
                    Description = "Operate processes and tooling to establish and maintain comprehensive network monitoring and defense."
                    Requirements = @(
                        @{
                            ID = "13.6"
                            Description = "Collect Network Traffic Flow Data"
                            Evaluator = { param($Results) $Results.Checks.ZeroTrust.MDCAIntegrated }
                            Impact = "Medium"
                            Recommendation = "Configure Microsoft Defender for Cloud Apps integration"
                        }
                    )
                },
                @{
                    Control = "14"
                    Title = "Security Awareness and Skills Training"
                    Description = "Establish and maintain a security awareness program."
                    Requirements = @(
                        @{
                            ID = "14.6"
                            Description = "Train Workforce on Secure Authentication"
                            Evaluator = { param($Results) $Results.Checks.UserMFA.BroadUserMFARequired }
                            Impact = "Medium"
                            Recommendation = "Implement MFA policies and security defaults"
                        }
                    )
                },
                @{
                    Control = "16"
                    Title = "Application Software Security"
                    Description = "Manage the security life cycle of all in-house developed and acquired software."
                    Requirements = @(
                        @{
                            ID = "16.9"
                            Description = "Separate Production and Non-Production Systems"
                            Evaluator = { param($Results) 
                                ($Results.Checks.SessionBindingPolicies | Where-Object { $_.AppCoverage -eq "Broad" }).Count -gt 0
                            }
                            Impact = "Medium"
                            Recommendation = "Implement app-specific Conditional Access policies"
                        }
                    )
                }
            ),
            # Microsoft MCRA (Microsoft Cybersecurity Reference Architecture)
            'MCRA' = @(
                @{
                    Control = "MCRA-IAM-1"
                    Title = "Strong Authentication"
                    Description = "Implement strong authentication mechanisms for all user accounts."
                    Requirements = @(
                        @{
                            ID = "MCRA-IAM-1.1"
                            Description = "Multi-factor authentication for all users"
                            Evaluator = { param($Results) $Results.Checks.UserMFA.BroadUserMFARequired }
                            Impact = "Critical"
                            Recommendation = "Deploy Conditional Access policies requiring MFA for all users"
                        },
                        @{
                            ID = "MCRA-IAM-1.2"
                            Description = "Passwordless authentication"
                            Evaluator = { param($Results) $Results.Checks.UserMFA.BroadUserMFARequired -and $Results.Checks.DeviceCompliance.BroadDeviceComplianceRequired }
                            Impact = "High"
                            Recommendation = "Configure combined device compliance and MFA policies"
                        }
                    )
                },
                @{
                    Control = "MCRA-IAM-2"
                    Title = "Privileged Access Management"
                    Description = "Secure and monitor privileged access to resources."
                    Requirements = @(
                        @{
                            ID = "MCRA-IAM-2.1"
                            Description = "Privileged accounts protection"
                            Evaluator = { param($Results) $Results.Checks.AdminMFA.AdminMFARequired }
                            Impact = "Critical"
                            Recommendation = "Implement MFA requirements for all administrative roles"
                        },
                        @{
                            ID = "MCRA-IAM-2.2"
                            Description = "Privileged session management"
                            Evaluator = { param($Results) 
                                $Results.Checks.AdminMFA.AdminMFARequired -and $Results.Checks.TokenBinding.TokenSessionBindingConfigured
                            }
                            Impact = "High"
                            Recommendation = "Configure session controls for privileged accounts"
                        }
                    )
                },
                @{
                    Control = "MCRA-IAM-3"
                    Title = "Risk-Based Access"
                    Description = "Implement adaptive authentication based on risk signals."
                    Requirements = @(
                        @{
                            ID = "MCRA-IAM-3.1"
                            Description = "Sign-in risk evaluation"
                            Evaluator = { param($Results) $Results.Checks.RiskPolicies.SignInRiskPoliciesConfigured }
                            Impact = "High"
                            Recommendation = "Configure sign-in risk-based Conditional Access policies"
                        },
                        @{
                            ID = "MCRA-IAM-3.2"
                            Description = "User risk evaluation"
                            Evaluator = { param($Results) $Results.Checks.RiskPolicies.UserRiskPoliciesConfigured }
                            Impact = "High"
                            Recommendation = "Configure user risk-based Conditional Access policies"
                        }
                    )
                },
                @{
                    Control = "MCRA-EP-1"
                    Title = "Endpoint Security"
                    Description = "Secure endpoints with comprehensive protection and management."
                    Requirements = @(
                        @{
                            ID = "MCRA-EP-1.1"
                            Description = "Device compliance"
                            Evaluator = { param($Results) $Results.Checks.DeviceCompliance.BroadDeviceComplianceRequired }
                            Impact = "High"
                            Recommendation = "Implement device compliance requirements for resource access"
                        }
                    )
                },
                @{
                    Control = "MCRA-DP-1"
                    Title = "Data Protection"
                    Description = "Protect data across all locations and states."
                    Requirements = @(
                        @{
                            ID = "MCRA-DP-1.1"
                            Description = "Mobile application management"
                            Evaluator = { param($Results) $Results.Checks.MAMPolicies.MAMPoliciesConfigured }
                            Impact = "Medium"
                            Recommendation = "Configure mobile application management policies"
                        }
                    )
                },
                @{
                    Control = "MCRA-NA-1"
                    Title = "Network Access"
                    Description = "Secure network access with Zero Trust principles."
                    Requirements = @(
                        @{
                            ID = "MCRA-NA-1.1"
                            Description = "Zero Trust Network Access"
                            Evaluator = { param($Results) 
                                $Results.Checks.ZeroTrust.MDCAIntegrated -or $Results.Checks.ZeroTrust.GlobalSecureAccessConfigured
                            }
                            Impact = "High"
                            Recommendation = "Configure Microsoft Defender for Cloud Apps and Global Secure Access"
                        }
                    )
                }
            ),
            # ISO 27001
            'ISO27001' = @(
                @{
                    Control = "A.9.2"
                    Title = "User Access Management"
                    Description = "To ensure authorized user access and to prevent unauthorized access to systems and services."
                    Requirements = @(
                        @{
                            ID = "A.9.2.1"
                            Description = "User registration and de-registration"
                            Evaluator = { param($Results) 
                                $Results.Checks.UserMFA.BroadUserMFARequired
                            }
                            Impact = "High"
                            Recommendation = "Implement access policies for all user accounts"
                        },
                        @{
                            ID = "A.9.2.3"
                            Description = "Management of privileged access rights"
                            Evaluator = { param($Results) $Results.Checks.AdminMFA.AdminMFARequired }
                            Impact = "Critical"
                            Recommendation = "Configure MFA requirements for administrative roles"
                        }
                    )
                },
                @{
                    Control = "A.9.4"
                    Title = "System and Application Access Control"
                    Description = "To prevent unauthorized access to systems and applications."
                    Requirements = @(
                        @{
                            ID = "A.9.4.2"
                            Description = "Secure log-on procedures"
                            Evaluator = { param($Results) $Results.Checks.UserMFA.BroadUserMFARequired }
                            Impact = "High"
                            Recommendation = "Implement MFA for all users"
                        },
                        @{
                            ID = "A.9.4.3"
                            Description = "Password management system"
                            Evaluator = { param($Results) 
                                $Results.Checks.UserMFA.BroadUserMFARequired -and $Results.Checks.RiskPolicies.UserRiskPoliciesConfigured
                            }
                            Impact = "Medium"
                            Recommendation = "Configure MFA and risk-based authentication"
                        }
                    )
                },
                @{
                    Control = "A.12.2"
                    Title = "Protection from Malware"
                    Description = "To ensure information and information processing facilities are protected against malware."
                    Requirements = @(
                        @{
                            ID = "A.12.2.1"
                            Description = "Controls against malware"
                            Evaluator = { param($Results) $Results.Checks.DeviceCompliance.BroadDeviceComplianceRequired }
                            Impact = "High"
                            Recommendation = "Implement device compliance policies"
                        }
                    )
                },
                @{
                    Control = "A.13.1"
                    Title = "Network Security Management"
                    Description = "To ensure the protection of information in networks and its supporting information processing facilities."
                    Requirements = @(
                        @{
                            ID = "A.13.1.1"
                            Description = "Network controls"
                            Evaluator = { param($Results) $Results.Checks.ZeroTrust.MDCAIntegrated }
                            Impact = "Medium"
                            Recommendation = "Configure Microsoft Defender for Cloud Apps integration"
                        }
                    )
                },
                @{
                    Control = "A.14.2"
                    Title = "Security in Development and Support Processes"
                    Description = "To ensure that information security is designed and implemented within the development lifecycle of information systems."
                    Requirements = @(
                        @{
                            ID = "A.14.2.1"
                            Description = "Secure development policy"
                            Evaluator = { param($Results) $Results.Checks.TokenBinding.TokenSessionBindingConfigured }
                            Impact = "Medium"
                            Recommendation = "Configure session controls for application access"
                        }
                    )
                }
            ),
            # PCI DSS
            'PCI' = @(
                @{
                    Control = "Requirement 8"
                    Title = "Identify and authenticate access to system components"
                    Description = "Ensure proper user identification and authentication management for users and administrators."
                    Requirements = @(
                        @{
                            ID = "8.3"
                            Description = "Secure all individual non-console administrative access using MFA"
                            Evaluator = { param($Results) $Results.Checks.AdminMFA.AdminMFARequired }
                            Impact = "Critical"
                            Recommendation = "Implement MFA for all administrative roles"
                        },
                        @{
                            ID = "8.5"
                            Description = "Do not use group, shared, or generic IDs or passwords"
                            Evaluator = { param($Results) $Results.Checks.UserMFA.BroadUserMFARequired }
                            Impact = "High"
                            Recommendation = "Implement MFA for all user accounts"
                        }
                    )
                },
                @{
                    Control = "Requirement 10"
                    Title = "Track and monitor all access to network resources and cardholder data"
                    Description = "Logging mechanisms and the ability to track user activities are critical in preventing and detecting potential security breaches."
                    Requirements = @(
                        @{
                            ID = "10.6"
                            Description = "Review logs and security events for all system components"
                            Evaluator = { param($Results) $Results.Checks.ZeroTrust.MDCAIntegrated }
                            Impact = "High"
                            Recommendation = "Configure Microsoft Defender for Cloud Apps integration"
                        }
                    )
                },
                @{
                    Control = "Requirement 11"
                    Title = "Regularly test security systems and processes"
                    Description = "Vulnerabilities are being discovered continually, and new updated malware is released regularly."
                    Requirements = @(
                        @{
                            ID = "11.5"
                            Description = "Deploy a change-detection mechanism to alert personnel to unauthorized modification"
                            Evaluator = { param($Results) $Results.Checks.RiskPolicies.UserRiskPoliciesConfigured }
                            Impact = "Medium"
                            Recommendation = "Configure user risk-based Conditional Access policies"
                        }
                    )
                }
            ),
            # HIPAA
            'HIPAA' = @(
                @{
                    Control = "Access Control - §164.312(a)(1)"
                    Title = "Technical safeguards for electronic protected health information"
                    Description = "Implement technical policies and procedures for electronic information systems that maintain ePHI to allow access only to authorized persons or software."
                    Requirements = @(
                        @{
                            ID = "164.312(a)(2)(i)"
                            Description = "Unique User Identification"
                            Evaluator = { param($Results) 
                                $Results.Checks.UserMFA.BroadUserMFARequired
                            }
                            Impact = "High"
                            Recommendation = "Implement MFA for all user accounts"
                        },
                        @{
                            ID = "164.312(a)(2)(ii)"
                            Description = "Emergency Access Procedure"
                            Evaluator = { param($Results) $Results.Checks.AdminMFA.AdminMFARequired }
                            Impact = "Critical"
                            Recommendation = "Configure emergency access accounts with appropriate protections"
                        },
                        @{
                            ID = "164.312(a)(2)(iv)"
                            Description = "Encryption and Decryption"
                            Evaluator = { param($Results) $Results.Checks.MAMPolicies.MAMPoliciesConfigured }
                            Impact = "High"
                            Recommendation = "Configure Mobile Application Management policies"
                        }
                    )
                },
                @{
                    Control = "Audit Controls - §164.312(b)"
                    Title = "Audit controls"
                    Description = "Implement hardware, software, and/or procedural mechanisms that record and examine activity in information systems containing ePHI."
                    Requirements = @(
                        @{
                            ID = "164.312(b)"
                            Description = "Activity monitoring"
                            Evaluator = { param($Results) 
                                $Results.Checks.RiskPolicies.SignInRiskPoliciesConfigured -and 
                                $Results.Checks.ZeroTrust.MDCAIntegrated
                            }
                            Impact = "High"
                            Recommendation = "Configure risk-based policies and Microsoft Defender for Cloud Apps"
                        }
                    )
                },
                @{
                    Control = "Integrity - §164.312(c)(1)"
                    Title = "Integrity controls"
                    Description = "Implement policies and procedures to protect ePHI from improper alteration or destruction."
                    Requirements = @(
                        @{
                            ID = "164.312(c)(2)"
                            Description = "Mechanism to authenticate ePHI"
                            Evaluator = { param($Results) $Results.Checks.DeviceCompliance.BroadDeviceComplianceRequired }
                            Impact = "Medium"
                            Recommendation = "Implement device compliance requirements"
                        }
                    )
                },
                @{
                    Control = "Person or Entity Authentication - §164.312(d)"
                    Title = "Authentication"
                    Description = "Implement procedures to verify that a person or entity seeking access to ePHI is the one claimed."
                    Requirements = @(
                        @{
                            ID = "164.312(d)"
                            Description = "Multi-factor authentication"
                            Evaluator = { param($Results) 
                                $Results.Checks.UserMFA.BroadUserMFARequired -and $Results.Checks.AdminMFA.AdminMFARequired
                            }
                            Impact = "Critical"
                            Recommendation = "Implement MFA for all users and administrative accounts"
                        }
                    )
                }
            )
        }
        
        # Helper function to evaluate benchmark compliance
        function Evaluate-BenchmarkCompliance {
            param (
                [Parameter(Mandatory = $true)]
                [string]$BenchmarkName,
                
                [Parameter(Mandatory = $true)]
                [PSCustomObject]$Results
            )
            
            $benchmarkData = $benchmarkControls[$BenchmarkName]
            $totalControls = 0
            $passedControls = 0
            $failedControls = 0
            
            $evaluationDetails = @()
            
            foreach ($control in $benchmarkData) {
                $controlPassed = $true
                $controlDetails = @()
                
                foreach ($requirement in $control.Requirements) {
                    $totalControls++
                    $result = & $requirement.Evaluator $Results
                    
                    if ($result) {
                        $passedControls++
                        $status = "PASS"
                    }
                    else {
                        $failedControls++
                        $status = "FAIL"
                        $controlPassed = $false
                    }
                    
                    $controlDetails += [PSCustomObject]@{
                        ID = $requirement.ID
                        Description = $requirement.Description
                        Status = $status
                        Impact = $requirement.Impact
                        Recommendation = $requirement.Recommendation
                    }
                }
                
                $evaluationDetails += [PSCustomObject]@{
                    Control = $control.Control
                    Title = $control.Title
                    Description = $control.Description
                    Status = if ($controlPassed) { "PASS" } else { "FAIL" }
                    Requirements = $controlDetails
                }
            }
            
            $complianceScore = if ($totalControls -gt 0) { 
                [math]::Round(($passedControls / $totalControls) * 100) 
            } else { 
                0 
            }
            
            return [PSCustomObject]@{
                BenchmarkName = $BenchmarkName
                TotalControls = $totalControls
                PassedControls = $passedControls
                FailedControls = $failedControls
                ComplianceScore = $complianceScore
                Details = $evaluationDetails
            }
        }
        
        # Helper function to convert benchmark results to HTML
        function Convert-BenchmarkToHtml {
            param(
                [Parameter(Mandatory = $true)]
                [PSCustomObject[]]$BenchmarkResults
            )
            
            $html = @"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Conditional Access Security Benchmark Report</title>
    <style>
        :root {
            --primary-color: #0078D4;
            --secondary-color: #50E6FF;
            --success-color: #107C10;
            --warning-color: #FF8C00;
            --danger-color: #E81123;
            --light-color: #F3F2F1;
            --dark-color: #201F1E;
            --font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
        }
        
        * {
            box-sizing: border-box;
            margin: 0;
            padding: 0;
        }
        
        body {
            font-family: var(--font-family);
            line-height: 1.6;
            color: var(--dark-color);
            background-color: #F9F9F9;
            margin: 0;
            padding: 0;
        }
        
        .container {
            width: 100%;
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
        }
        
        header {
            background-color: var(--primary-color);
            color: white;
            padding: 20px 0;
            margin-bottom: 30px;
        }
        
        h1, h2, h3, h4, h5, h6 {
            font-weight: 600;
            line-height: 1.3;
            margin-bottom: 15px;
            color: var(--primary-color);
        }
        
        h1 {
            font-size: 2.5rem;
            color: white;
            margin-bottom: 5px;
        }
        
        h2 {
            font-size: 1.8rem;
            border-bottom: 2px solid var(--primary-color);
            padding-bottom: 10px;
            margin-top: 40px;
        }
        
        h3 {
            font-size: 1.4rem;
            margin-top: 30px;
        }
        
        h4 {
            font-size: 1.2rem;
            margin-top: 25px;
        }
        
        p {
            margin-bottom: 15px;
        }
        
        .card {
            background-color: white;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0, 0, 0, 0.1);
            margin-bottom: 30px;
            overflow: hidden;
        }
        
        .card-header {
            background-color: var(--primary-color);
            color: white;
            padding: 15px 20px;
            font-size: 1.2rem;
            font-weight: 600;
        }
        
        .card-body {
            padding: 20px;
        }
        
        .dashboard {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        
        .metric-card {
            background-color: white;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0, 0, 0, 0.1);
            padding: 20px;
            text-align: center;
        }
        
        .metric-title {
            font-size: 1rem;
            color: var(--dark-color);
            margin-bottom: 10px;
        }
        
        .metric-value {
            font-size: 2.2rem;
            font-weight: bold;
            margin-bottom: 10px;
        }
        
        .chart-container {
            position: relative;
            margin: 0 auto;
            width: 160px;
            height: 160px;
        }
        
        .score-chart {
            position: relative;
            width: 100%;
            height: 100%;
        }
        
        .score-background {
            fill: none;
            stroke: #E0E0E0;
            stroke-width: 10;
        }
        
        .score-circle {
            fill: none;
            stroke-width: 10;
            stroke-linecap: round;
            transform: rotate(-90deg);
            transform-origin: center;
            transition: stroke-dashoffset 1s ease-in-out;
        }
        
        .score-text {
            font-size: 2.5rem;
            font-weight: bold;
            text-anchor: middle;
            dominant-baseline: middle;
        }
        
        .score-label {
            font-size: 1rem;
            text-anchor: middle;
            dominant-baseline: middle;
            fill: #666;
        }
        
        .table-container {
            overflow-x: auto;
            margin-bottom: 30px;
        }
        
        table {
            width: 100%;
            border-collapse: collapse;
            margin-bottom: 20px;
        }
        
        th, td {
            padding: 12px 15px;
            text-align: left;
            border-bottom: 1px solid #E0E0E0;
        }
        
        th {
            background-color: #F5F5F5;
            font-weight: 600;
            color: var(--primary-color);
        }
        
        tr:hover {
            background-color: #F9F9F9;
        }
        
        .status-pass {
            color: var(--success-color);
            font-weight: 600;
        }
        
        .status-fail {
            color: var(--danger-color);
            font-weight: 600;
        }
        
        .impact-critical {
            background-color: rgba(232, 17, 35, 0.1);
        }
        
        .impact-high {
            background-color: rgba(255, 140, 0, 0.1);
        }
        
        .impact-medium {
            background-color: rgba(255, 185, 0, 0.1);
        }
        
        .impact-low {
            background-color: rgba(16, 124, 16, 0.1);
        }
        
        .check-details {
            margin-top: 15px;
            border: 1px solid #E0E0E0;
            border-radius: 5px;
            overflow: hidden;
        }
        
        .check-details-header {
            background-color: #F5F5F5;
            padding: 10px 15px;
            cursor: pointer;
            display: flex;
            justify-content: space-between;
            align-items: center;
            font-weight: 600;
        }
        
        .check-details-body {
            padding: 15px;
            display: none;
        }
        
        .check-details.active .check-details-body {
            display: block;
        }
        
        .collapsible-arrow {
            transition: transform 0.3s ease;
        }
        
        .check-details.active .collapsible-arrow {
            transform: rotate(180deg);
        }
        
        .footer {
            background-color: var(--light-color);
            padding: 20px;
            text-align: center;
            margin-top: 50px;
            color: #666;
        }
        
        /* Tabs */
        .tabs {
            display: flex;
            border-bottom: 1px solid #ddd;
            margin-bottom: 20px;
        }
        
        .tab {
            padding: 10px 20px;
            cursor: pointer;
            border: 1px solid transparent;
            border-bottom: none;
            margin-bottom: -1px;
            background-color: transparent;
            font-weight: 600;
        }
        
        .tab.active {
            border-color: #ddd;
            border-radius: 5px 5px 0 0;
            background-color: white;
            color: var(--primary-color);
        }
        
        .tab-content {
            display: none;
            padding: 20px 0;
        }
        
        .tab-content.active {
            display: block;
        }
    </style>
</head>
<body>
    <header>
        <div class="container">
            <h1>Conditional Access Security Benchmark Report</h1>
            <p>Generated on $(Get-Date -Format "MMMM d, yyyy HH:mm:ss")</p>
        </div>
    </header>
    
    <div class="container">
        <div class="dashboard">
"@
            
            # Add benchmark score cards
            foreach ($result in $BenchmarkResults) {
                $scoreColor = if ($result.ComplianceScore -ge 90) { "#107C10" } 
                              elseif ($result.ComplianceScore -ge 70) { "#FF8C00" }
                              else { "#E81123" }
                
                $html += @"
            <div class="metric-card">
                <div class="chart-container">
                    <svg class="score-chart" viewBox="0 0 100 100">
                        <circle class="score-background" cx="50" cy="50" r="40"></circle>
                        <circle class="score-circle" cx="50" cy="50" r="40" 
                            stroke="$scoreColor" 
                            stroke-dasharray="251.2" 
                            stroke-dashoffset="$(251.2 - (251.2 * $result.ComplianceScore / 100))">
                        </circle>
                        <text x="50" y="50" class="score-text" fill="$scoreColor">$($result.ComplianceScore)%</text>
                    </svg>
                </div>
                <div class="metric-title">$($result.BenchmarkName) Compliance</div>
                <div class="metric-subtitle">
                    Passed: $($result.PassedControls)/$($result.TotalControls) controls
                </div>
            </div>
"@
            }
            
            $html += @"
        </div>
        
        <div class="tabs">
"@
            
            # Add benchmark tabs
            for ($i = 0; $i -lt $BenchmarkResults.Count; $i++) {
                $isActive = if ($i -eq 0) { "active" } else { "" }
                $html += @"
            <div class="tab $isActive" data-tab="tab-$i">$($BenchmarkResults[$i].BenchmarkName)</div>
"@
            }
            
            $html += @"
        </div>
"@
            
            # Add benchmark details
            for ($i = 0; $i -lt $BenchmarkResults.Count; $i++) {
                $result = $BenchmarkResults[$i]
                $isActive = if ($i -eq 0) { "active" } else { "" }
                
                $html += @"
        <div class="tab-content $isActive" id="tab-$i">
            <div class="card">
                <div class="card-header">$($result.BenchmarkName) Compliance Summary</div>
                <div class="card-body">
                    <p><strong>Total Controls:</strong> $($result.TotalControls)</p>
                    <p><strong>Passed Controls:</strong> $($result.PassedControls)</p>
                    <p><strong>Failed Controls:</strong> $($result.FailedControls)</p>
                    <p><strong>Compliance Score:</strong> $($result.ComplianceScore)%</p>
                </div>
            </div>
            
            <h3>$($result.BenchmarkName) Control Details</h3>
"@
                
                foreach ($control in $result.Details) {
                    $statusClass = if ($control.Status -eq "PASS") { "status-pass" } else { "status-fail" }
                    $isActiveControl = if ($control.Status -eq "FAIL") { "active" } else { "" }
                    
                    $html += @"
            <div class="check-details $isActiveControl">
                <div class="check-details-header">
                    <div>
                        <span class="$statusClass">[$($control.Status)]</span>
                        $($control.Control): $($control.Title)
                    </div>
                    <span class="collapsible-arrow">▼</span>
                </div>
                <div class="check-details-body">
                    <p>$($control.Description)</p>
                    
                    <h4>Requirements</h4>
                    <div class="table-container">
                        <table>
                            <thead>
                                <tr>
                                    <th>ID</th>
                                    <th>Description</th>
                                    <th>Status</th>
                                    <th>Impact</th>
                                    <th>Recommendation</th>
                                </tr>
                            </thead>
                            <tbody>
"@
                    
                    foreach ($requirement in $control.Requirements) {
                        $reqStatusClass = if ($requirement.Status -eq "PASS") { "status-pass" } else { "status-fail" }
                        $impactClass = "impact-" + $requirement.Impact.ToLower()
                        
                        $html += @"
                                <tr class="$impactClass">
                                    <td>$($requirement.ID)</td>
                                    <td>$($requirement.Description)</td>
                                    <td class="$reqStatusClass">$($requirement.Status)</td>
                                    <td>$($requirement.Impact)</td>
                                    <td>$($requirement.Recommendation)</td>
                                </tr>
"@
                    }
                    
                    $html += @"
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>
"@
                }
                
                $html += @"
        </div>
"@
            }
            
            $html += @"
    </div>
    
    <div class="footer">
        <p>Conditional Access Analyzer Security Benchmark Report</p>
        <p>Generated on $(Get-Date -Format "MMMM d, yyyy") using Conditional Access Analyzer PowerShell Module</p>
    </div>
    
    <script>
        // Tab switching
        document.querySelectorAll('.tab').forEach(tab => {
            tab.addEventListener('click', function() {
                // Remove active class from all tabs
                document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
                // Add active class to clicked tab
                this.classList.add('active');
                
                // Hide all tab content
                document.querySelectorAll('.tab-content').forEach(content => content.classList.remove('active'));
                // Show corresponding tab content
                document.getElementById(this.getAttribute('data-tab')).classList.add('active');
            });
        });
        
        // Check details collapsible
        document.querySelectorAll('.check-details-header').forEach(header => {
            header.addEventListener('click', function() {
                const parent = this.parentElement;
                parent.classList.toggle('active');
            });
        });
    </script>
</body>
</html>
"@
            
            return $html
        }
    }
    
    process {
        try {
            # Display benchmark evaluation header
            $benchmarkList = if ($BenchmarkName -eq 'All') {
                $benchmarkControls.Keys
            } else {
                @($BenchmarkName)
            }
            
            Write-Host "Evaluating Conditional Access configuration against security benchmarks..." -ForegroundColor Cyan
            
            # Evaluate benchmarks
            $benchmarkResults = @()
            foreach ($benchmark in $benchmarkList) {
                Write-Host "`nEvaluating against $benchmark benchmark..." -ForegroundColor Yellow
                $results = Evaluate-BenchmarkCompliance -BenchmarkName $benchmark -Results $Results
                
                # Display summary
                Write-Host "  - Total Controls: $($results.TotalControls)" -ForegroundColor White
                Write-Host "  - Passed Controls: $($results.PassedControls)" -ForegroundColor Green
                Write-Host "  - Failed Controls: $($results.FailedControls)" -ForegroundColor Red
                Write-Host "  - Compliance Score: $($results.ComplianceScore)%" -ForegroundColor $(
                    if ($results.ComplianceScore -ge 90) { "Green" }
                    elseif ($results.ComplianceScore -ge 70) { "Yellow" }
                    else { "Red" }
                )
                
                $benchmarkResults += $results
                
                # Display detailed results if requested
                if ($IncludeDetails) {
                    Write-Host "`n  Control Details:" -ForegroundColor Yellow
                    
                    foreach ($control in $results.Details) {
                        $statusSymbol = if ($control.Status -eq "PASS") { "✓" } else { "✗" }
                        $statusColor = if ($control.Status -eq "PASS") { "Green" } else { "Red" }
                        
                        Write-Host "    [$statusSymbol] $($control.Control): $($control.Title)" -ForegroundColor $statusColor
                        
                        if ($control.Status -eq "FAIL") {
                            Write-Host "      - Description: $($control.Description)" -ForegroundColor White
                            
                            Write-Host "      - Failed Requirements:" -ForegroundColor Yellow
                            $failedReqs = $control.Requirements | Where-Object { $_.Status -eq "FAIL" }
                            
                            foreach ($req in $failedReqs) {
                                Write-Host "        * $($req.ID): $($req.Description)" -ForegroundColor White
                                Write-Host "          Impact: $($req.Impact)" -ForegroundColor $(
                                    if ($req.Impact -eq "Critical") { "Red" }
                                    elseif ($req.Impact -eq "High") { "DarkRed" }
                                    else { "Yellow" }
                                )
                                Write-Host "          Recommendation: $($req.Recommendation)" -ForegroundColor Cyan
                            }
                        }
                    }
                }
            }
            
            # Create HTML report if output path is specified
            if ($OutputPath) {
                Write-Host "`nGenerating benchmark report..." -ForegroundColor Yellow
                
                $html = Convert-BenchmarkToHtml -BenchmarkResults $benchmarkResults
                Set-Content -Path $OutputPath -Value $html -Encoding UTF8
                
                Write-Host "Report saved to $OutputPath" -ForegroundColor Green
            }
            
            # Return results
            return $benchmarkResults
        }
        catch {
            Write-Error "Failed to evaluate against security benchmarks: $_"
            throw
        }
    }
}

function Export-CAComplianceDashboard {
    <#
    .SYNOPSIS
        Exports a comprehensive Conditional Access compliance dashboard.
    .DESCRIPTION
        Generates an interactive HTML dashboard combining compliance check results,
        benchmark evaluations, and trend analysis to provide a complete security
        overview.
    .PARAMETER Results
        The compliance check results to include. If not specified, Invoke-CAComplianceCheck is run.
    .PARAMETER BenchmarkResults
        The benchmark evaluation results to include. If not specified and IncludeBenchmarks is specified,
        Test-CASecurityBenchmark is run with All benchmarks.
    .PARAMETER HistoricalResults
        An array of previous compliance check results for trend analysis.
    .PARAMETER IncludeBenchmarks
        If specified, includes security benchmark evaluations in the dashboard.
    .PARAMETER IncludeRemediation
        If specified, includes detailed remediation recommendations.
    .PARAMETER CompanyName
        Optional company name to include in the dashboard.
    .PARAMETER BrandingLogo
        Optional URL or path to a logo image to include in the dashboard.
    .PARAMETER OutputPath
        The file path where the dashboard should be saved. If not specified, a default location is used.
    .PARAMETER OpenDashboard
        If specified, the dashboard is opened after generation.
    .EXAMPLE
        Export-CAComplianceDashboard -IncludeBenchmarks -OutputPath "C:\Reports\CADashboard.html" -OpenDashboard
        Generates a comprehensive dashboard including benchmark evaluations.
    .NOTES
        The dashboard provides a central view of all security aspects of the Conditional Access
        configuration, making it ideal for security reviews and management presentations.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [PSCustomObject]$Results,
        
        [Parameter(Mandatory = $false)]
        [PSCustomObject[]]$BenchmarkResults,
        
        [Parameter(Mandatory = $false)]
        [PSCustomObject[]]$HistoricalResults,
        
        [Parameter(Mandatory = $false)]
        [switch]$IncludeBenchmarks,
        
        [Parameter(Mandatory = $false)]
        [switch]$IncludeRemediation,
        
        [Parameter(Mandatory = $false)]
        [string]$CompanyName,
        
        [Parameter(Mandatory = $false)]
        [string]$BrandingLogo,
        
        [Parameter(Mandatory = $false)]
        [string]$OutputPath,
        
        [Parameter(Mandatory = $false)]
        [switch]$OpenDashboard
    )
    
    begin {
        # Verify connection
        if (-not (Test-CAAnalyzerConnection)) {
            throw "Not connected to Microsoft Graph. Use Connect-CAAnalyzer first."
        }
        
        # If no results provided, run the compliance check
        if (-not $Results) {
            Write-Host "No results provided. Running comprehensive Conditional Access compliance check..." -ForegroundColor Yellow
            $Results = Invoke-CAComplianceCheck
        }
        
        # If including benchmarks but no benchmark results provided, run the benchmark check
        if ($IncludeBenchmarks -and (-not $BenchmarkResults)) {
            Write-Host "No benchmark results provided. Running security benchmark evaluation..." -ForegroundColor Yellow
            $BenchmarkResults = Test-CASecurityBenchmark -BenchmarkName 'All'
        }
        
        # Set default path if not specified
        if (-not $OutputPath) {
            $timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
            $fileName = "CA-Compliance-Dashboard-$timestamp.html"
            
            # Use a sensible default location
            $documentsPath = [Environment]::GetFolderPath('MyDocuments')
            $reportsFolder = Join-Path -Path $documentsPath -ChildPath "CA-Reports"
            
            # Create the reports folder if it doesn't exist
            if (-not (Test-Path -Path $reportsFolder)) {
                New-Item -Path $reportsFolder -ItemType Directory -Force | Out-Null
            }
            
            $OutputPath = Join-Path -Path $reportsFolder -ChildPath $fileName
        }
        
        # Set company name if not specified
        if (-not $CompanyName) {
            try {
                $tenantInfo = Get-MgOrganization
                $CompanyName = $tenantInfo.DisplayName
            }
            catch {
                $CompanyName = "Your Organization"
                Write-Warning "Could not retrieve organization name. Using default: $CompanyName"
            }
        }
    }
    
    process {
        try {
            Write-Host "Generating comprehensive Conditional Access compliance dashboard..." -ForegroundColor Cyan
            
            # Generate dashboard HTML
            $html = Generate-ComplianceDashboardHtml -Results $Results -BenchmarkResults $BenchmarkResults -HistoricalResults $HistoricalResults -IncludeRemediation:$IncludeRemediation -CompanyName $CompanyName -BrandingLogo $BrandingLogo
            
            # Save dashboard
            Set-Content -Path $OutputPath -Value $html -Encoding UTF8
            
            Write-Host "Dashboard saved to $OutputPath" -ForegroundColor Green
            
            # Open dashboard if requested
            if ($OpenDashboard) {
                Start-Process $OutputPath
            }
            
            return @{
                DashboardPath = $OutputPath
                GeneratedTime = Get-Date
                IncludesBenchmarks = $IncludeBenchmarks.IsPresent
                IncludesRemediation = $IncludeRemediation.IsPresent
            }
        }
        catch {
            Write-Error "Failed to generate Conditional Access compliance dashboard: $_"
            throw
        }
    }
    
    end {
        function Generate-ComplianceDashboardHtml {
    <#
    .SYNOPSIS
        Generates an HTML dashboard for Conditional Access compliance results.
    .DESCRIPTION
        Creates a rich, interactive HTML dashboard that visualizes Conditional Access
        compliance results, benchmark evaluations, and trend analysis.
    .PARAMETER Results
        The compliance check results to include in the dashboard.
    .PARAMETER BenchmarkResults
        The benchmark evaluation results to include in the dashboard.
    .PARAMETER HistoricalResults
        An array of previous compliance check results for trend analysis.
    .PARAMETER IncludeRemediation
        If specified, includes detailed remediation recommendations.
    .PARAMETER CompanyName
        Optional company name to include in the dashboard.
    .PARAMETER BrandingLogo
        Optional URL or path to a logo image to include in the dashboard.
    .EXAMPLE
        Generate-ComplianceDashboardHtml -Results $results -BenchmarkResults $benchmarkResults
    .NOTES
        This function creates a standalone HTML file with embedded CSS and JavaScript.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$Results,
        
        [Parameter(Mandatory = $false)]
        [PSCustomObject[]]$BenchmarkResults,
        
        [Parameter(Mandatory = $false)]
        [PSCustomObject[]]$HistoricalResults,
        
        [Parameter(Mandatory = $false)]
        [switch]$IncludeRemediation,
        
        [Parameter(Mandatory = $false)]
        [string]$CompanyName,
        
        [Parameter(Mandatory = $false)]
        [string]$BrandingLogo
    )
    
    # Define score color function
    $getScoreColor = {
        param($score)
        if ($score -ge 90) { return "#107C10" } # Green
        elseif ($score -ge 75) { return "#FF8C00" } # Orange
        elseif ($score -ge 60) { return "#FFC83D" } # Yellow
        else { return "#E81123" } # Red
    }
    
    # Set company name if not provided
    if (-not $CompanyName) {
        $CompanyName = $Results.TenantName
    }
    
    # Determine score level
    $scoreLevel = switch ($Results.ComplianceScore) {
        {$_ -ge 90} { "Excellent" }
        {$_ -ge 80} { "Good" }
        {$_ -ge 70} { "Fair" }
        {$_ -ge 60} { "Poor" }
        default { "Critical" }
    }
    
    $scoreColor = & $getScoreColor $Results.ComplianceScore
    
    # Prepare recommendations
    $recommendations = @()
    
    if (-not $Results.Checks.AdminMFA.AdminMFARequired) {
        $recommendations += [PSCustomObject]@{
            Priority = "Critical"
            Category = "Identity Protection"
            Title = "Admin MFA Enforcement"
            Description = $Results.Checks.AdminMFA.Recommendation
        }
    }
    
    if (-not $Results.Checks.UserMFA.BroadUserMFARequired) {
        $recommendations += [PSCustomObject]@{
            Priority = "High"
            Category = "Identity Protection"
            Title = "User MFA Enforcement"
            Description = $Results.Checks.UserMFA.Recommendation
        }
    }
    
    if (-not $Results.Checks.DeviceCompliance.BroadDeviceComplianceRequired) {
        $recommendations += [PSCustomObject]@{
            Priority = "High"
            Category = "Device Trust"
            Title = "Device Compliance"
            Description = $Results.Checks.DeviceCompliance.Recommendation
        }
    }
    
    if (-not $Results.Checks.RiskPolicies.SignInRiskPoliciesConfigured -or
        -not $Results.Checks.RiskPolicies.UserRiskPoliciesConfigured) {
        $recommendations += [PSCustomObject]@{
            Priority = "High"
            Category = "Risk-Based Access"
            Title = "Risk-Based Access"
            Description = $Results.Checks.RiskPolicies.Recommendation
        }
    }
    
    if (-not $Results.Checks.TokenBinding.TokenSessionBindingConfigured) {
        $recommendations += [PSCustomObject]@{
            Priority = "Medium"
            Category = "Session Security"
            Title = "Token Session Binding"
            Description = $Results.Checks.TokenBinding.Recommendation
        }
    }
    
    if (-not $Results.Checks.MAMPolicies.MAMPoliciesConfigured) {
        $recommendations += [PSCustomObject]@{
            Priority = "Medium"
            Category = "Data Protection"
            Title = "Mobile Application Management"
            Description = $Results.Checks.MAMPolicies.Recommendation
        }
    }
    
    if (-not $Results.Checks.ZeroTrust.MDCAIntegrated -or
        -not $Results.Checks.ZeroTrust.GlobalSecureAccessConfigured) {
        $recommendations += [PSCustomObject]@{
            Priority = "Medium"
            Category = "Network Security"
            Title = "Zero Trust Network Access"
            Description = $Results.Checks.ZeroTrust.Recommendation
        }
    }
    
    # Start building HTML
    $html = @"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Conditional Access Compliance Dashboard - $CompanyName</title>
    <style>
        :root {
            --primary-color: #0078D4;
            --secondary-color: #50E6FF;
            --success-color: #107C10;
            --warning-color: #FF8C00;
            --danger-color: #E81123;
            --light-color: #F3F2F1;
            --dark-color: #201F1E;
            --font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
        }
        
        * {
            box-sizing: border-box;
            margin: 0;
            padding: 0;
        }
        
        body {
            font-family: var(--font-family);
            line-height: 1.6;
            color: var(--dark-color);
            background-color: #F9F9F9;
            margin: 0;
            padding: 0;
        }
        
        .container {
            width: 100%;
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
        }
        
        header {
            background-color: var(--primary-color);
            color: white;
            padding: 20px 0;
            margin-bottom: 30px;
        }
        
        h1, h2, h3, h4, h5, h6 {
            font-weight: 600;
            line-height: 1.3;
            margin-bottom: 15px;
            color: var(--primary-color);
        }
        
        h1 {
            font-size: 2.5rem;
            color: white;
            margin-bottom: 5px;
        }
        
        h2 {
            font-size: 1.8rem;
            border-bottom: 2px solid var(--primary-color);
            padding-bottom: 10px;
            margin-top: 40px;
        }
        
        h3 {
            font-size: 1.4rem;
            margin-top: 30px;
        }
        
        p {
            margin-bottom: 15px;
        }
        
        .dashboard {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        
        .score-card {
            background-color: white;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0, 0, 0, 0.1);
            padding: 20px;
            text-align: center;
            display: flex;
            flex-direction: column;
            align-items: center;
            justify-content: center;
        }
        
        .score-circle {
            width: 150px;
            height: 150px;
            border-radius: 50%;
            background-color: #f2f2f2;
            display: flex;
            flex-direction: column;
            justify-content: center;
            align-items: center;
            margin-bottom: 20px;
            position: relative;
        }
        
        .score-circle::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            border-radius: 50%;
            background: conic-gradient($scoreColor 0% calc($($Results.ComplianceScore) * 1%), #f2f2f2 calc($($Results.ComplianceScore) * 1%) 100%);
            mask: radial-gradient(transparent 65%, black 66%);
            -webkit-mask: radial-gradient(transparent 65%, black 66%);
        }
        
        .score-circle-inner {
            width: 120px;
            height: 120px;
            border-radius: 50%;
            background-color: white;
            display: flex;
            flex-direction: column;
            justify-content: center;
            align-items: center;
            box-shadow: 0 2px 10px rgba(0, 0, 0, 0.1);
            z-index: 1;
        }
        
        .score-value {
            font-size: 2.5rem;
            font-weight: bold;
            color: $scoreColor;
        }
        
        .score-label {
            font-size: 1rem;
            color: #666;
        }
        
        .score-title {
            font-size: 1.2rem;
            font-weight: bold;
            margin-bottom: 5px;
        }
        
        .score-summary {
            font-size: 1rem;
            color: #666;
        }
        
        .card {
            background-color: white;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0, 0, 0, 0.1);
            margin-bottom: 20px;
            overflow: hidden;
        }
        
        .card-header {
            background-color: var(--primary-color);
            color: white;
            padding: 15px 20px;
            font-size: 1.2rem;
            font-weight: 600;
        }
        
        .card-body {
            padding: 20px;
        }
        
        .security-checks {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        
        .check-item {
            background-color: white;
            border-radius: 8px;
            box-shadow: 0 2px 5px rgba(0, 0, 0, 0.1);
            padding: 15px;
            display: flex;
            flex-direction: column;
        }
        
        .check-title {
            font-weight: bold;
            margin-bottom: 10px;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        
        .check-status {
            padding: 3px 8px;
            border-radius: 4px;
            font-size: 0.8rem;
            font-weight: bold;
        }
        
        .status-pass {
            background-color: #ecf7ec;
            color: var(--success-color);
        }
        
        .status-fail {
            background-color: #fdeaea;
            color: var(--danger-color);
        }
        
        .check-description {
            margin-bottom: 10px;
            color: #666;
        }
        
        .recommendations {
            margin-top: 40px;
        }
        
        .recommendation-item {
            background-color: white;
            border-radius: 8px;
            box-shadow: 0 2px 5px rgba(0, 0, 0, 0.1);
            padding: 15px;
            margin-bottom: 15px;
            border-left: 4px solid;
        }
        
        .priority-critical {
            border-left-color: var(--danger-color);
        }
        
        .priority-high {
            border-left-color: var(--warning-color);
        }
        
        .priority-medium {
            border-left-color: #FFC83D;
        }
        
        .recommendation-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 10px;
        }
        
        .recommendation-title {
            font-weight: bold;
        }
        
        .recommendation-priority {
            padding: 3px 8px;
            border-radius: 4px;
            font-size: 0.8rem;
        }
        
        .priority-badge-critical {
            background-color: #fdeaea;
            color: var(--danger-color);
        }
        
        .priority-badge-high {
            background-color: #fff5e6;
            color: var(--warning-color);
        }
        
        .priority-badge-medium {
            background-color: #fffaeb;
            color: #9C6500;
        }
        
        .recommendation-category {
            font-size: 0.9rem;
            color: #666;
            margin-bottom: 10px;
        }
        
        .recommendation-description {
            color: #333;
        }
        
        .footer {
            background-color: var(--light-color);
            padding: 20px;
            text-align: center;
            margin-top: 50px;
            color: #666;
        }
        
        .tabs {
            display: flex;
            border-bottom: 1px solid #ddd;
            margin-bottom: 20px;
        }
        
        .tab {
            padding: 10px 20px;
            cursor: pointer;
            border: 1px solid transparent;
            border-bottom: none;
            margin-bottom: -1px;
            background-color: transparent;
            font-weight: 600;
        }
        
        .tab.active {
            border-color: #ddd;
            border-radius: 5px 5px 0 0;
            background-color: white;
            color: var(--primary-color);
        }
        
        .tab-content {
            display: none;
            padding: 20px 0;
        }
        
        .tab-content.active {
            display: block;
        }
        
        @media (max-width: 768px) {
            .dashboard {
                grid-template-columns: 1fr;
            }
            
            .security-checks {
                grid-template-columns: 1fr;
            }
        }
    </style>
</head>
<body>
    <header>
        <div class="container">
            <h1>Conditional Access Compliance Dashboard</h1>
            <p>Tenant: $($Results.TenantName) | Generated on $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")</p>
        </div>
    </header>
    
    <div class="container">
        <div class="dashboard">
"@

    # Add main score card
    $html += @"
            <div class="score-card">
                <div class="score-circle">
                    <div class="score-circle-inner">
                        <div class="score-value">$($Results.ComplianceScore)%</div>
                        <div class="score-label">$scoreLevel</div>
                    </div>
                </div>
                <div class="score-title">Overall Compliance</div>
                <div class="score-summary">Based on Zero Trust principles</div>
            </div>
"@

    # Add score cards for security pillars
    $securityPillars = @(
        @{
            Name = "Identity Protection"
            Score = [math]::Round(([int]$Results.Checks.AdminMFA.AdminMFARequired + [int]$Results.Checks.UserMFA.BroadUserMFARequired) / 2 * 100)
        },
        @{
            Name = "Device Trust"
            Score = [math]::Round([int]$Results.Checks.DeviceCompliance.BroadDeviceComplianceRequired * 100)
        },
        @{
            Name = "Risk-Based Access"
            Score = [math]::Round(([int]$Results.Checks.RiskPolicies.SignInRiskPoliciesConfigured + [int]$Results.Checks.RiskPolicies.UserRiskPoliciesConfigured) / 2 * 100)
        },
        @{
            Name = "Session Security"
            Score = [math]::Round([int]$Results.Checks.TokenBinding.TokenSessionBindingConfigured * 100)
        }
    )

    foreach ($pillar in $securityPillars) {
        $pillarColor = & $getScoreColor $pillar.Score
        
        $html += @"
            <div class="score-card">
                <div class="score-circle">
                    <div class="score-circle-inner">
                        <div class="score-value" style="color: $pillarColor;">$($pillar.Score)%</div>
                    </div>
                </div>
                <div class="score-title">$($pillar.Name)</div>
            </div>
"@
    }

    $html += @"
        </div>
        
        <div class="card">
            <div class="card-header">Security Checks</div>
            <div class="card-body">
                <div class="security-checks">
"@

    # Add security checks
    $securityChecks = @(
        @{
            Title = "Admin MFA Required"
            Status = $Results.Checks.AdminMFA.AdminMFARequired
            Description = "Multi-factor authentication for administrative roles"
            Recommendation = $Results.Checks.AdminMFA.Recommendation
        },
        @{
            Title = "User MFA Required"
            Status = $Results.Checks.UserMFA.BroadUserMFARequired
            Description = "Multi-factor authentication for all users"
            Recommendation = $Results.Checks.UserMFA.Recommendation
        },
        @{
            Title = "Device Compliance Required"
            Status = $Results.Checks.DeviceCompliance.BroadDeviceComplianceRequired
            Description = "Device compliance verification for resource access"
            Recommendation = $Results.Checks.DeviceCompliance.Recommendation
        },
        @{
            Title = "Sign-in Risk Policy"
            Status = $Results.Checks.RiskPolicies.SignInRiskPoliciesConfigured
            Description = "Policies that respond to suspicious sign-in attempts"
            Recommendation = "Configure CA policy based on sign-in risk"
        },
        @{
            Title = "User Risk Policy"
            Status = $Results.Checks.RiskPolicies.UserRiskPoliciesConfigured
            Description = "Policies that respond to compromised user accounts"
            Recommendation = "Configure CA policy based on user risk"
        },
        @{
            Title = "Token Session Binding"
            Status = $Results.Checks.TokenBinding.TokenSessionBindingConfigured
            Description = "Session controls for authentication token security"
            Recommendation = $Results.Checks.TokenBinding.Recommendation
        }
    )

    foreach ($check in $securityChecks) {
        $statusClass = if ($check.Status) { "status-pass" } else { "status-fail" }
        $statusText = if ($check.Status) { "PASS" } else { "FAIL" }
        
        $html += @"
                    <div class="check-item">
                        <div class="check-title">
                            $($check.Title)
                            <span class="check-status $statusClass">$statusText</span>
                        </div>
                        <div class="check-description">$($check.Description)</div>
                        $(if (-not $check.Status) { "<div class='check-recommendation'>$($check.Recommendation)</div>" })
                    </div>
"@
    }

    $html += @"
                </div>
            </div>
        </div>
"@

    # Add recommendations if they exist
    if ($recommendations.Count -gt 0) {
        $html += @"
        <div class="recommendations">
            <h2>Security Recommendations</h2>
"@

        foreach ($recommendation in $recommendations) {
            $priorityClass = "priority-$($recommendation.Priority.ToLower())"
            $priorityBadgeClass = "priority-badge-$($recommendation.Priority.ToLower())"
            
            $html += @"
            <div class="recommendation-item $priorityClass">
                <div class="recommendation-header">
                    <div class="recommendation-title">$($recommendation.Title)</div>
                    <div class="recommendation-priority $priorityBadgeClass">$($recommendation.Priority)</div>
                </div>
                <div class="recommendation-category">$($recommendation.Category)</div>
                <div class="recommendation-description">$($recommendation.Description)</div>
            </div>
"@
        }

        $html += @"
        </div>
"@
    }

    # Add benchmarks if provided
    if ($BenchmarkResults -and $BenchmarkResults.Count -gt 0) {
        $html += @"
        <h2>Security Benchmark Results</h2>
        
        <div class="tabs">
"@

        for ($i = 0; $i -lt $BenchmarkResults.Count; $i++) {
            $activeClass = if ($i -eq 0) { "active" } else { "" }
            $html += @"
            <div class="tab $activeClass" data-tab="tab-$i">$($BenchmarkResults[$i].BenchmarkName)</div>
"@
        }

        $html += @"
        </div>
"@

        for ($i = 0; $i -lt $BenchmarkResults.Count; $i++) {
            $benchmark = $BenchmarkResults[$i]
            $activeClass = if ($i -eq 0) { "active" } else { "" }
            
            $html += @"
        <div class="tab-content $activeClass" id="tab-$i">
            <div class="card">
                <div class="card-header">$($benchmark.BenchmarkName) Compliance</div>
                <div class="card-body">
                    <p><strong>Overall Score:</strong> $($benchmark.OverallScore)%</p>
                    <p><strong>Compliant Controls:</strong> $($benchmark.CompliantControls) of $($benchmark.TotalControls)</p>
                </div>
            </div>
        </div>
"@
        }
    }

    # Add historical trend analysis if provided
    if ($HistoricalResults -and $HistoricalResults.Count -gt 0) {
        $html += @"
        <h2>Compliance Trend Analysis</h2>
        
        <div class="card">
            <div class="card-header">Compliance Score Over Time</div>
            <div class="card-body">
                <canvas id="trendChart" width="400" height="200"></canvas>
            </div>
        </div>
        
        <script src="https://cdn.jsdelivr.net/npm/chart.js@3.7.1/dist/chart.min.js"></script>
        <script>
            document.addEventListener('DOMContentLoaded', function() {
                const ctx = document.getElementById('trendChart').getContext('2d');
                
                const data = {
                    labels: [
                        $(($HistoricalResults | ForEach-Object { "'" + $_.EvaluationDate.ToString("yyyy-MM-dd") + "'" }) -join ', ')
                    ],
                    datasets: [{
                        label: 'Compliance Score',
                        data: [
                            $(($HistoricalResults | ForEach-Object { $_.ComplianceScore }) -join ', ')
                        ],
                        fill: false,
                        borderColor: '#0078D4',
                        tension: 0.1
                    }]
                };
                
                const config = {
                    type: 'line',
                    data: data,
                    options: {
                        scales: {
                            y: {
                                beginAtZero: true,
                                max: 100
                            }
                        },
                        plugins: {
                            legend: {
                                display: true,
                                position: 'top'
                            }
                        }
                    }
                };
                
                const myChart = new Chart(ctx, config);
            });
        </script>
"@
    }

    # Add remediation section if requested
    if ($IncludeRemediation) {
        $html += @"
        <h2>Remediation Plan</h2>
        
        <div class="card">
            <div class="card-header">Recommended Remediation Steps</div>
            <div class="card-body">
                <p>The following remediation steps are recommended to address the identified issues:</p>
                
                <ol>
"@

        foreach ($recommendation in $recommendations | Sort-Object -Property Priority) {
            $remediation = switch ($recommendation.Category) {
                "Identity Protection" { 
                    if ($recommendation.Title -like "*Admin*") {
                        "New-CABestPracticePolicy -PolicyType AdminMFA -DeployPolicy"
                    } else {
                        "New-CABestPracticePolicy -PolicyType UserMFA -DeployPolicy"
                    }
                }
                "Device Trust" { "New-CABestPracticePolicy -PolicyType DeviceCompliance -DeployPolicy" }
                "Risk-Based Access" { 
                    if ($recommendation.Title -like "*Sign-in*") {
                        "New-CABestPracticePolicy -PolicyType SignInRisk -DeployPolicy"
                    } else {
                        "New-CABestPracticePolicy -PolicyType UserRisk -DeployPolicy"
                    }
                }
                "Session Security" { "New-CABestPracticePolicy -PolicyType TokenBinding -DeployPolicy" }
                "Data Protection" { "New-CABestPracticePolicy -PolicyType MAMPolicy -DeployPolicy" }
                "Network Security" { 
                    if ($recommendation.Title -like "*MDCA*") {
                        "New-CABestPracticePolicy -PolicyType CloudAppSecurity -DeployPolicy"
                    } else {
                        "New-CABestPracticePolicy -PolicyType GlobalSecureAccess -DeployPolicy"
                    }
                }
                default { "Invoke-CAComplianceRemediation -IncludeAll" }
            }
            
            $html += @"
                    <li>
                        <strong>$($recommendation.Title)</strong> - $($recommendation.Description)
                        <div class="code-block">$remediation</div>
                    </li>
"@
        }

        $html += @"
                </ol>
                
                <p class="warning">Note: Deploy policies in report-only mode first to assess impact.</p>
                <pre>Invoke-CAComplianceRemediation -RemediateAll -DeployInReportOnlyMode</pre>
            </div>
        </div>
"@
    }

    $html += @"
        <div class="footer">
            <p>Conditional Access Analyzer Report</p>
            <p>Generated on $(Get-Date -Format "yyyy-MM-dd") using Conditional Access Analyzer PowerShell Module</p>
        </div>
    </div>
    
    <script>
        // Tab switching
        document.addEventListener('DOMContentLoaded', function() {
            const tabs = document.querySelectorAll('.tab');
            
            tabs.forEach(tab => {
                tab.addEventListener('click', function() {
                    // Remove active class from all tabs
                    tabs.forEach(t => t.classList.remove('active'));
                    // Add active class to clicked tab
                    this.classList.add('active');
                    
                    // Hide all tab content
                    const tabContents = document.querySelectorAll('.tab-content');
                    tabContents.forEach(content => content.classList.remove('active'));
                    
                    // Show corresponding tab content
                    document.getElementById(this.getAttribute('data-tab')).classList.add('active');
                });
            });
        });
    </script>
</body>
</html>
"@

    return $html
}
    }
}
