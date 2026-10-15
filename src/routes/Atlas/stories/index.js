/**
 * Atlas Stories Registry
 *
 * Central registry for all visualization stories.
 * Stories define how to visualize data from providers.
 */

import authReconTargetsStory from './authReconTargets'
import securityPostureStory from './securityPosture'

/**
 * All available stories
 */
const stories = {
  'authrecon-targets': authReconTargetsStory,
  'security-posture': securityPostureStory,
}

/**
 * Default story to show
 */
export const DEFAULT_STORY_ID = 'authrecon-targets'

/**
 * Get a story by ID
 * @param {string} storyId - Story identifier
 * @returns {Object|null} Story configuration
 */
export const getStory = (storyId) => {
  return stories[storyId] || null
}

/**
 * Get all available stories
 * @returns {Object[]} Array of story summaries
 */
export const getAllStories = () => {
  return Object.values(stories).map((s) => ({
    id: s.id,
    name: s.name,
    description: s.description,
    provider: s.provider,
    icon: s.icon,
  }))
}

/**
 * Get stories for a specific provider
 * @param {string} providerId - Provider identifier
 * @returns {Object[]} Array of stories for the provider
 */
export const getStoriesForProvider = (providerId) => {
  return Object.values(stories)
    .filter((s) => s.provider === providerId)
    .map((s) => ({
      id: s.id,
      name: s.name,
      description: s.description,
      icon: s.icon,
    }))
}

/**
 * Local storage key for persisting selected story
 */
export const STORY_STORAGE_KEY = 'atlas-selected-story'

/**
 * Get the persisted story ID from localStorage
 * @returns {string} Story ID
 */
export const getPersistedStory = () => {
  try {
    const stored = localStorage.getItem(STORY_STORAGE_KEY)
    if (stored && stories[stored]) {
      return stored
    }
  } catch {
    // localStorage not available
  }
  return DEFAULT_STORY_ID
}

/**
 * Persist the selected story ID to localStorage
 * @param {string} storyId - Story ID to persist
 */
export const persistStory = (storyId) => {
  try {
    localStorage.setItem(STORY_STORAGE_KEY, storyId)
  } catch {
    // localStorage not available
  }
}

export default {
  stories,
  DEFAULT_STORY_ID,
  getStory,
  getAllStories,
  getStoriesForProvider,
  getPersistedStory,
  persistStory,
}
