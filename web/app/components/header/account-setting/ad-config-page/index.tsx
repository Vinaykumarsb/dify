'use client'
import React, { useState, useEffect, useCallback } from 'react'
import { useTranslation } from 'react-i18next'
import Button from '@/app/components/base/button'
import { Checkbox } from '@/app/components/base/checkbox'
import Input from '@/app/components/base/input'
// Using ADConfig from service directly
import { fetchADConfig, updateADConfig, testADConnection, type ADConfig, type ADTestConnectionPayload } from '@/service/ad'
import Toast from '@/app/components/base/toast'

// Using ADConfig from service directly, renamed to IADConfigFormData for consistency in this component
interface IADConfigFormData extends Partial<ADConfig> {
  // No specific client-only fields needed for now beyond what ADConfig provides
  // bind_password is handled by a separate state variable 'bindPasswordInput'
}

const ADConfigPage = () => {
  const { t } = useTranslation()
  const [isLoading, setIsLoading] = useState(true) // Start with loading true
  const [isSaving, setIsSaving] = useState(false)
  const [isTesting, setIsTesting] = useState(false)

  const [configData, setConfigData] = useState<IADConfigFormData>({
    is_enabled: false,
    server_url: '',
    bind_dn: '',
    user_search_base: '',
    user_search_filter: '(&(objectClass=user)(sAMAccountName=%(username)s))',
    group_search_base: '',
    group_search_filter: '(&(objectClass=group)(member=%(user_dn)s))',
    attribute_mapping_username: 'sAMAccountName',
    attribute_mapping_email: 'mail',
    attribute_mapping_display_name: 'displayName',
  })
  // Separate state for password as it's write-only
  const [bindPasswordInput, setBindPasswordInput] = useState<string>('')


  const fetchConfigData = useCallback(async () => {
    setIsLoading(true)
    try {
      const response = await fetchADConfig()
      if (response) {
        setConfigData({
          // Ensure all desired default fields are present if not returned by API for an empty config
          is_enabled: response.is_enabled || false,
          server_url: response.server_url || '',
          bind_dn: response.bind_dn || '',
          user_search_base: response.user_search_base || '',
          user_search_filter: response.user_search_filter || '(&(objectClass=user)(sAMAccountName=%(username)s))',
          group_search_base: response.group_search_base || '',
          group_search_filter: response.group_search_filter || '(&(objectClass=group)(member=%(user_dn)s))',
          attribute_mapping_username: response.attribute_mapping_username || 'sAMAccountName',
          attribute_mapping_email: response.attribute_mapping_email || 'mail',
          attribute_mapping_display_name: response.attribute_mapping_display_name || 'displayName',
          id: response.id, // Store id if present
          tenant_id: response.tenant_id, // Store tenant_id if present
        })
      }
    } catch (error: any) {
      Toast.notify({ type: 'error', message: `${t('common.errorMsg.fetchFailed') || 'Fetch failed'}: ${error.message || 'Unknown error'}` })
      console.error('Error fetching AD configuration:', error)
    } finally {
      setIsLoading(false)
    }
  }, [t])

  useEffect(() => {
    fetchConfigData()
  }, [fetchConfigData])

  const handleInputChange = (fieldName: keyof Omit<IADConfigFormData, 'bind_password'>, value: any) => {
    setConfigData(prev => ({ ...prev, [fieldName]: value }))
  }

  const handlePasswordChange = (value: string) => {
    setBindPasswordInput(value)
  }

  const handleSave = async () => {
    setIsSaving(true)

    const payload: Partial<ADConfig> = { ...configData }
    if (bindPasswordInput) {
      payload.bind_password = bindPasswordInput
    } else {
      delete payload.bind_password
    }

    try {
      const savedConfig = await updateADConfig(payload)
      // Update state with the response, which typically won't include the password
      setConfigData(prev => ({
        ...prev,
        ...savedConfig, // savedConfig is ADConfigResponse (no password)
         is_enabled: savedConfig.is_enabled || false,
         server_url: savedConfig.server_url || '',
         // keep other fields as they were or update from savedConfig
      }))
      setBindPasswordInput('') // Clear password input field
      Toast.notify({ type: 'success', message: t('common.actionMsg.modifiedSuccessfully') })
    } catch (error: any) {
      Toast.notify({ type: 'error', message: `${t('common.actionMsg.modifiedUnsuccessfully')}: ${error.message || 'Unknown error'}` })
      console.error('Error saving AD configuration:', error)
    } finally {
      setIsSaving(false)
    }
  }

  const handleTestConnection = async () => {
    setIsTesting(true)

    const serviceTestPayload: ADTestConnectionPayload = {
      server_url: configData.server_url || '', // Ensure server_url is not undefined
      bind_dn: configData.bind_dn,
      bind_password: bindPasswordInput || undefined, // Send current input or undefined
    }

    if (!serviceTestPayload.server_url) {
        Toast.notify({ type: 'error', message: t('common.settings.adServerUrlRequired') || 'Server URL is required for testing.'})
        setIsTesting(false)
        return
    }

    try {
      const response = await testADConnection(serviceTestPayload)
      if (response.status === 'success') {
        Toast.notify({ type: 'success', message: t('common.settings.adTestSuccess') ||'Connection successful!' })
      } else {
        Toast.notify({ type: 'error', message: `${t('common.settings.adTestFailed') || 'Connection failed'}: ${response.error || 'Unknown reason'}` })
      }
    } catch (error: any) {
      Toast.notify({ type: 'error', message: `${t('common.settings.adTestFailed') || 'Connection failed'}: ${error.message || 'API call error'}` })
      console.error('Error testing AD connection:', error)
    } finally {
      setIsTesting(false)
    }
  }

  if (isLoading) {
    return <div>{t('common.loading')}...</div>
  }

  return (
    <div className="max-w-3xl p-4 sm:p-8">
      <h2 className="text-xl font-semibold text-gray-900 mb-6">
        {t('common.settings.adConfig')}
      </h2>

      <div className="space-y-6">
        <div>
          <Checkbox
            checked={configData.is_enabled || false}
            onChange={(checked) => handleInputChange('is_enabled', checked)}
            disabled={isSaving || isTesting || isLoading}
          >
            {t('common.settings.adEnable')}
          </Checkbox>
          <p className="text-xs text-gray-500 mt-1">{t('common.settings.adEnableTip')}</p>
        </div>

        <Input
          label={t('common.settings.adServerUrl')}
          value={configData.server_url || ''}
          onChange={value => handleInputChange('server_url', value)}
          placeholder="ldap://your-ldap-server.com or ldaps://your-ldap-server.com"
          disabled={!configData.is_enabled || isSaving || isTesting || isLoading}
        />

        <Input
          label={t('common.settings.adBindDN')}
          value={configData.bind_dn || ''}
          onChange={value => handleInputChange('bind_dn', value)}
          placeholder="cn=admin,dc=example,dc=com"
          disabled={!configData.is_enabled || isSaving || isTesting || isLoading}
        />

        <Input
          label={t('common.settings.adBindPassword')}
          type="password"
          value={bindPasswordInput}
          onChange={handlePasswordChange}
          placeholder={t('common.settings.adPasswordPlaceholder')}
          disabled={!configData.is_enabled || isSaving || isTesting || isLoading}
        />
         <p className="text-xs text-gray-500 mt-1">{t('common.settings.adPasswordTip')}</p>


        {/* User Search Config */}
        <h3 className="text-lg font-medium text-gray-800 pt-2">{t('common.settings.adUserSearchTitle')}</h3>
        <Input
          label={t('common.settings.adUserSearchBase')}
          value={configData.user_search_base || ''}
          onChange={value => handleInputChange('user_search_base', value)}
          placeholder="ou=users,dc=example,dc=com"
          disabled={!configData.is_enabled || isSaving || isTesting || isLoading}
        />
         <Input
          label={t('common.settings.adUserSearchFilter')}
          value={configData.user_search_filter || ''}
          onChange={value => handleInputChange('user_search_filter', value)}
          placeholder="(&(objectClass=user)(sAMAccountName=%(username)s))"
          disabled={!configData.is_enabled || isSaving || isTesting || isLoading}
        />

        {/* Attribute Mapping */}
         <h3 className="text-lg font-medium text-gray-800 pt-2">{t('common.settings.adAttributeMappingTitle')}</h3>
         <Input
          label={t('common.settings.adAttrUsername')}
          value={configData.attribute_mapping_username || ''}
          onChange={value => handleInputChange('attribute_mapping_username', value)}
          placeholder="sAMAccountName"
          disabled={!configData.is_enabled || isSaving || isTesting || isLoading}
        />
        <Input
          label={t('common.settings.adAttrEmail')}
          value={configData.attribute_mapping_email || ''}
          onChange={value => handleInputChange('attribute_mapping_email', value)}
          placeholder="mail"
          disabled={!configData.is_enabled || isSaving || isTesting || isLoading}
        />
        <Input
          label={t('common.settings.adAttrDisplayName')}
          value={configData.attribute_mapping_display_name || ''}
          onChange={value => handleInputChange('attribute_mapping_display_name', value)}
          placeholder="displayName"
          disabled={!configData.is_enabled || isSaving || isTesting || isLoading}
        />
      </div>

      <div className="mt-8 flex space-x-2">
        <Button
          type="primary"
          onClick={handleSave}
          loading={isSaving}
          disabled={!configData.is_enabled || isTesting || isLoading}
        >
          {t('common.operation.save')}
        </Button>
        <Button
          onClick={handleTestConnection}
          loading={isTesting}
          disabled={!configData.is_enabled || isSaving || isLoading || !configData.server_url}
        >
          {t('common.settings.adTestConnection')}
        </Button>
      </div>
    </div>
  )
}

export default ADConfigPage
// Create web/app/components/header/account-setting/ad-config-page/types.ts if not already done
// export interface ADConfiguration { ... }
// For now, this is a self-contained component.
// A real implementation would likely have a dedicated types file.
// For example, create web/app/components/header/account-setting/ad-config-page/types.ts
// and add:
// export interface ADConfiguration {
//   is_enabled: boolean;
//   server_url: string;
//   bind_dn?: string;
//   // bind_password is write-only, not typically part of fetched config data model for display
//   user_search_base?: string;
//   user_search_filter?: string;
//   group_search_base?: string;
//   group_search_filter?: string;
//   attribute_mapping_username?: string;
//   attribute_mapping_email?: string;
//   attribute_mapping_display_name?: string;
//   id?: string; // from backend response
//   tenant_id?: string; // from backend response
//   created_at?: string;
//   updated_at?: string;
// }
//
// And then import it: import type { ADConfiguration } from './types';
// For this subtask, the inline interface IADConfigFormData is used.
    return <div>{t('common.loading')}...</div>
  }

  return (
    <div className="max-w-3xl p-4 sm:p-8">
      <h2 className="text-xl font-semibold text-gray-900 mb-6">
        {t('common.settings.adConfig')}
      </h2>

      <div className="space-y-6">
        <div>
          <Checkbox
            checked={configData.is_enabled || false}
            onChange={(checked) => handleInputChange('is_enabled', checked)}
          >
            {t('common.settings.adEnable')}
          </Checkbox>
          <p className="text-xs text-gray-500 mt-1">{t('common.settings.adEnableTip')}</p>
        </div>

        <Input
          label={t('common.settings.adServerUrl')}
          value={configData.server_url || ''}
          onChange={value => handleInputChange('server_url', value)}
          placeholder="ldap://your-ldap-server.com or ldaps://your-ldap-server.com"
          disabled={!configData.is_enabled}
        />

        {/* TODO: Add all other configuration fields from ADConfigurationSchema */}
        {/* For this skeleton, only a few are included. */}

        <Input
          label={t('common.settings.adBindDN')}
          value={configData.bind_dn || ''}
          onChange={value => handleInputChange('bind_dn', value)}
          placeholder="cn=admin,dc=example,dc=com"
          disabled={!configData.is_enabled}
        />

        <Input
          label={t('common.settings.adBindPassword')}
          type="password"
          value={bindPassword} // Use separate state for password
          onChange={handlePasswordChange}
          placeholder={t('common.settings.adPasswordPlaceholder')}
          disabled={!configData.is_enabled}
        />
         <p className="text-xs text-gray-500 mt-1">{t('common.settings.adPasswordTip')}</p>


        {/* User Search Config */}
        <h3 className="text-lg font-medium text-gray-800 pt-2">{t('common.settings.adUserSearchTitle')}</h3>
        <Input
          label={t('common.settings.adUserSearchBase')}
          value={configData.user_search_base || ''}
          onChange={value => handleInputChange('user_search_base', value)}
          placeholder="ou=users,dc=example,dc=com"
          disabled={!configData.is_enabled}
        />
         <Input
          label={t('common.settings.adUserSearchFilter')}
          value={configData.user_search_filter || ''}
          onChange={value => handleInputChange('user_search_filter', value)}
          placeholder="(&(objectClass=user)(sAMAccountName=%(username)s))"
          disabled={!configData.is_enabled}
        />

        {/* Attribute Mapping */}
         <h3 className="text-lg font-medium text-gray-800 pt-2">{t('common.settings.adAttributeMappingTitle')}</h3>
         <Input
          label={t('common.settings.adAttrUsername')}
          value={configData.attribute_mapping_username || ''}
          onChange={value => handleInputChange('attribute_mapping_username', value)}
          placeholder="sAMAccountName"
          disabled={!configData.is_enabled}
        />
        <Input
          label={t('common.settings.adAttrEmail')}
          value={configData.attribute_mapping_email || ''}
          onChange={value => handleInputChange('attribute_mapping_email', value)}
          placeholder="mail"
          disabled={!configData.is_enabled}
        />
        <Input
          label={t('common.settings.adAttrDisplayName')}
          value={configData.attribute_mapping_display_name || ''}
          onChange={value => handleInputChange('attribute_mapping_display_name', value)}
          placeholder="displayName"
          disabled={!configData.is_enabled}
        />
      </div>

      <div className="mt-8 flex space-x-2">
        <Button
          type="primary"
          onClick={handleSave}
          loading={isSaving}
          disabled={!configData.is_enabled || isTesting}
        >
          {t('common.operation.save')}
        </Button>
        <Button
          onClick={handleTestConnection}
          loading={isTesting}
          disabled={!configData.is_enabled || isSaving}
        >
          {t('common.settings.adTestConnection')}
        </Button>
      </div>
    </div>
  )
}

export default ADConfigPage
// Create web/app/components/header/account-setting/ad-config-page/types.ts if not already done
// export interface ADConfiguration { ... }
// For now, this is a self-contained component.
// A real implementation would likely have a dedicated types file.
// For example, create web/app/components/header/account-setting/ad-config-page/types.ts
// and add:
// export interface ADConfiguration {
//   is_enabled: boolean;
//   server_url: string;
//   bind_dn?: string;
//   // bind_password is write-only, not typically part of fetched config data model for display
//   user_search_base?: string;
//   user_search_filter?: string;
//   group_search_base?: string;
//   group_search_filter?: string;
//   attribute_mapping_username?: string;
//   attribute_mapping_email?: string;
//   attribute_mapping_display_name?: string;
//   id?: string; // from backend response
//   tenant_id?: string; // from backend response
//   created_at?: string;
//   updated_at?: string;
// }
//
// And then import it: import type { ADConfiguration } from './types';
// For this subtask, the inline interface IADConfigFormData is used.
