import React from 'react';
import {mount} from 'enzyme';

import {BackButton} from 'app/views/settings/components/settingsBackButton';

describe('SettingsBackButton', function() {
  const project = TestStubs.Project();
  const org = TestStubs.Organization();

  it('renders "Back to Project" when given project slug', function() {
    let wrapper = mount(<BackButton params={{}} organization={org} project={project} />);
    expect(wrapper.find('BackButtonWrapper').text()).toBe(' Back to Project');
    expect(wrapper.find('BackButtonWrapper').prop('to')).toBe('/org-slug/project-slug/');
  });

  it('renders "Back to Organization" when no project slug', function() {
    let wrapper = mount(<BackButton params={{}} organization={org} project={null} />);
    expect(wrapper.find('BackButtonWrapper').text()).toBe(' Back to Organization');
    expect(wrapper.find('BackButtonWrapper').prop('to')).toBe('/org-slug/');
  });

  it('uses "last route" when provided', function() {
    let wrapper = mount(
      <BackButton
        lastRoute="/org-slug/project-slug/foo/bar/"
        params={{}}
        organization={org}
        project={project}
      />
    );
    expect(wrapper.find('BackButtonWrapper').prop('to')).toBe(
      '/org-slug/project-slug/foo/bar/'
    );
  });
});
