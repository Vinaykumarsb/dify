import React from 'react'
import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import '@testing-library/jest-dom'
import { I18nextProvider } from 'react-i18next'
import i18n from '@/i18n/i18next-config' // Adjust path if your config is elsewhere
import ADConfigPage from '.' // The component to test

// Mock the services
jest.mock('@/service/ad', () => ({
  fetchADConfig: jest.fn(),
  updateADConfig: jest.fn(),
  testADConnection: jest.fn(),
}))

// Mock the Toast component
jest.mock('@/app/components/base/toast', () => ({
  notify: jest.fn(),
}))

// Import the mocked functions to use in tests
import { fetchADConfig, updateADConfig, testADConnection } from '@/service/ad'
import Toast from '@/app/components/base/toast'

const mockFetchADConfig = fetchADConfig as jest.Mock
const mockUpdateADConfig = updateADConfig as jest.Mock
const mockTestADConnection = testADConnection as jest.Mock
const mockToastNotify = Toast.notify as jest.Mock

// Helper to render with i18n provider
const renderWithI18n = (component: React.ReactElement) => {
  return render(<I18nextProvider i18n={i18n}>{component}</I18nextProvider>)
}

describe('ADConfigPage', () => {
  beforeEach(() => {
    // Reset mocks before each test
    mockFetchADConfig.mockReset()
    mockUpdateADConfig.mockReset()
    mockTestADConnection.mockReset()
    mockToastNotify.mockReset()
  })

  describe('Initial Render & Data Load', () => {
    it('should render and populate form with fetched data', async () => {
      const sampleConfig = {
        is_enabled: true,
        server_url: 'ldap://test.example.com',
        bind_dn: 'cn=admin,dc=example,dc=com',
        user_search_base: 'ou=users,dc=example,dc=com',
        user_search_filter: '(&(objectClass=inetOrgPerson)(uid=%(username)s))',
        attribute_mapping_username: 'uid',
        attribute_mapping_email: 'mail',
        attribute_mapping_display_name: 'cn',
      }
      mockFetchADConfig.mockResolvedValue(sampleConfig)

      renderWithI18n(<ADConfigPage />)

      // Wait for loading to finish and data to populate
      expect(screen.getByText('common.loading...')).toBeInTheDocument() // Initial loading
      await waitFor(() => expect(screen.queryByText('common.loading...')).not.toBeInTheDocument())

      await waitFor(() => {
        expect((screen.getByLabelText('common.settings.adServerUrl') as HTMLInputElement).value).toBe(sampleConfig.server_url)
      })
      expect((screen.getByRole('checkbox', { name: 'common.settings.adEnable' }) as HTMLInputElement).checked).toBe(true)
      expect((screen.getByLabelText('common.settings.adBindDN') as HTMLInputElement).value).toBe(sampleConfig.bind_dn)
      expect((screen.getByLabelText('common.settings.adUserSearchBase') as HTMLInputElement).value).toBe(sample_config.user_search_base)
      // ... check other fields
    })

    it('should show error toast if fetchADConfig fails', async () => {
      mockFetchADConfig.mockRejectedValue(new Error('Fetch error'))
      renderWithI18n(<ADConfigPage />)

      await waitFor(() => {
        expect(mockToastNotify).toHaveBeenCalledWith({
          type: 'error',
          message: 'common.errorMsg.fetchFailed: Fetch error',
        })
      })
    })
  })

  describe('Form Input Interaction', () => {
    it('should update state on input change', async () => {
      mockFetchADConfig.mockResolvedValue({ is_enabled: false, server_url: '' }) // Initial load
      renderWithI18n(<ADConfigPage />)
      await waitFor(() => expect(screen.queryByText('common.loading...')).not.toBeInTheDocument())

      // Test checkbox
      const enableCheckbox = screen.getByRole('checkbox', { name: 'common.settings.adEnable' })
      fireEvent.click(enableCheckbox)
      expect((enableCheckbox as HTMLInputElement).checked).toBe(true)

      // Test text input
      const serverUrlInput = screen.getByLabelText('common.settings.adServerUrl')
      fireEvent.change(serverUrlInput, { target: { value: 'ldap://new.server.com' } })
      expect((serverUrlInput as HTMLInputElement).value).toBe('ldap://new.server.com')

      const bindPasswordInput = screen.getByLabelText('common.settings.adBindPassword')
      fireEvent.change(bindPasswordInput, { target: { value: 'new_password' } })
      expect((bindPasswordInput as HTMLInputElement).value).toBe('new_password')
    })
  })

  describe('Save Configuration (handleSave)', () => {
    it('should call updateADConfig with correct payload and show success toast', async () => {
      const initialConfig = { is_enabled: true, server_url: 'ldap://initial.com' }
      mockFetchADConfig.mockResolvedValue(initialConfig)
      mockUpdateADConfig.mockResolvedValue({ ...initialConfig, server_url: 'ldap://updated.com' }) // Simulate response

      renderWithI18n(<ADConfigPage />)
      await waitFor(() => expect(screen.queryByText('common.loading...')).not.toBeInTheDocument())

      // Change some data
      fireEvent.change(screen.getByLabelText('common.settings.adServerUrl'), { target: { value: 'ldap://updated.com' } })
      fireEvent.change(screen.getByLabelText('common.settings.adBindPassword'), { target: { value: 'securepass' } })

      fireEvent.click(screen.getByRole('button', { name: 'common.operation.save' }))

      await waitFor(() => {
        expect(mockUpdateADConfig).toHaveBeenCalledWith(expect.objectContaining({
          is_enabled: true,
          server_url: 'ldap://updated.com',
          bind_password: 'securepass', // Password included
        }))
      })
      await waitFor(() => {
        expect(mockToastNotify).toHaveBeenCalledWith({
          type: 'success',
          message: 'common.actionMsg.modifiedSuccessfully',
        })
      })
      // Check if password field is cleared (assuming bindPasswordInput state is used for the input value)
      expect((screen.getByLabelText('common.settings.adBindPassword') as HTMLInputElement).value).toBe('')
    })

    it('should call updateADConfig without password if not changed', async () => {
      mockFetchADConfig.mockResolvedValue({ is_enabled: true, server_url: 'ldap://initial.com' })
      mockUpdateADConfig.mockResolvedValue({ is_enabled: true, server_url: 'ldap://new.url.com' })

      renderWithI18n(<ADConfigPage />)
      await waitFor(() => expect(screen.queryByText('common.loading...')).not.toBeInTheDocument())

      fireEvent.change(screen.getByLabelText('common.settings.adServerUrl'), { target: { value: 'ldap://new.url.com' } })
      // Password input field is not touched

      fireEvent.click(screen.getByRole('button', { name: 'common.operation.save' }))

      await waitFor(() => {
        const expectedPayload = expect.objectContaining({
          is_enabled: true,
          server_url: 'ldap://new.url.com',
        })
        // Ensure 'bind_password' is not part of the payload
        const actualPayload = mockUpdateADConfig.mock.calls[0][0];
        expect(actualPayload).toEqual(expectedPayload);
        expect(actualPayload.bind_password).toBeUndefined();
      })
    })

    it('should show error toast if updateADConfig fails', async () => {
      mockFetchADConfig.mockResolvedValue({ is_enabled: true, server_url: 'ldap://initial.com' })
      mockUpdateADConfig.mockRejectedValue(new Error('Update failed'))

      renderWithI18n(<ADConfigPage />)
      await waitFor(() => expect(screen.queryByText('common.loading...')).not.toBeInTheDocument())

      fireEvent.click(screen.getByRole('button', { name: 'common.operation.save' }))

      await waitFor(() => {
        expect(mockToastNotify).toHaveBeenCalledWith({
          type: 'error',
          message: 'common.actionMsg.modifiedUnsuccessfully: Update failed',
        })
      })
    })
  })

  describe('Test Connection (handleTestConnection)', () => {
    it('should call testADConnection and show success toast', async () => {
      mockFetchADConfig.mockResolvedValue({ is_enabled: true, server_url: 'ldap://test.com' })
      mockTestADConnection.mockResolvedValue({ status: 'success' })

      renderWithI18n(<ADConfigPage />)
      await waitFor(() => expect(screen.queryByText('common.loading...')).not.toBeInTheDocument())

      fireEvent.change(screen.getByLabelText('common.settings.adServerUrl'), { target: { value: 'ldap://test.com' } })
      fireEvent.change(screen.getByLabelText('common.settings.adBindPassword'), { target: { value: 'testpass' } })

      fireEvent.click(screen.getByRole('button', { name: 'common.settings.adTestConnection' }))

      await waitFor(() => {
        expect(mockTestADConnection).toHaveBeenCalledWith({
          server_url: 'ldap://test.com',
          bind_dn: undefined, // Assuming it wasn't filled in this specific test path
          bind_password: 'testpass',
        })
      })
      await waitFor(() => {
        expect(mockToastNotify).toHaveBeenCalledWith({
          type: 'success',
          message: 'common.settings.adTestSuccess',
        })
      })
    })

    it('should call testADConnection and show failure toast with error message', async () => {
      mockFetchADConfig.mockResolvedValue({ is_enabled: true, server_url: 'ldap://test.com' })
      mockTestADConnection.mockResolvedValue({ status: 'failure', error: 'Test LDAP Error' })
      renderWithI18n(<ADConfigPage />)
      await waitFor(() => expect(screen.queryByText('common.loading...')).not.toBeInTheDocument())

      fireEvent.click(screen.getByRole('button', { name: 'common.settings.adTestConnection' }))

      await waitFor(() => {
        expect(mockToastNotify).toHaveBeenCalledWith({
          type: 'error',
          message: 'common.settings.adTestFailed: Test LDAP Error',
        })
      })
    })
  })

  describe('Loading States', () => {
    it('should disable buttons during save operation', async () => {
      mockFetchADConfig.mockResolvedValue({ is_enabled: true, server_url: 'ldap://initial.com' });
      // Make updateADConfig promise never resolve for this test to check loading state
      mockUpdateADConfig.mockImplementation(() => new Promise(() => {}));

      renderWithI18n(<ADConfigPage />);
      await waitFor(() => expect(screen.queryByText('common.loading...')).not.toBeInTheDocument());

      const saveButton = screen.getByRole('button', { name: 'common.operation.save' });
      const testButton = screen.getByRole('button', { name: 'common.settings.adTestConnection' });

      fireEvent.click(saveButton);

      expect(saveButton).toBeDisabled();
      expect(testButton).toBeDisabled(); // Also disable test button during save
      // Check for loading indicator if your Button component supports it visually
      // e.g., expect(saveButton).toHaveClass('loading');
    });

    it('should disable buttons during test connection operation', async () => {
      mockFetchADConfig.mockResolvedValue({ is_enabled: true, server_url: 'ldap://initial.com' });
      mockTestADConnection.mockImplementation(() => new Promise(() => {}));

      renderWithI18n(<ADConfigPage />);
      await waitFor(() => expect(screen.queryByText('common.loading...')).not.toBeInTheDocument());

      const saveButton = screen.getByRole('button', { name: 'common.operation.save' });
      const testButton = screen.getByRole('button', { name: 'common.settings.adTestConnection' });

      fireEvent.click(testButton);

      expect(testButton).toBeDisabled();
      expect(saveButton).toBeDisabled(); // Also disable save button during test
    });
  });

})
