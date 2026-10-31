package org.example.examples.shopping.presentation.screen.lists

import androidx.compose.foundation.text.input.clearText
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import dev.zacsweers.metro.AppScope
import dev.zacsweers.metro.ContributesIntoMap
import dev.zacsweers.metro.Inject
import dev.zacsweers.metro.binding
import dev.zacsweers.metrox.viewmodel.ViewModelKey
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.*
import kotlinx.coroutines.launch
import org.example.examples.shopping.data.db.entity.Category
import org.example.examples.shopping.data.db.entity.ItemCategory
import org.example.examples.shopping.data.db.entity.ShoppingItem
import org.example.examples.shopping.data.session.ShoppingNode
import org.example.examples.shopping.data.session.ShoppingSession
import org.example.examples.shopping.presentation.screen.NodeViewModel
import rocky.room.settledOnRocky

@Inject
@ViewModelKey
@ContributesIntoMap(AppScope::class, binding = binding<ViewModel>())
@OptIn(ExperimentalCoroutinesApi::class)
class ListsViewModel(session: ShoppingSession) : NodeViewModel(session) {
    private val selection = MutableStateFlow<Long?>(null)
    val editor = ListsEditor()

    val state: StateFlow<ListsState> = node.flatMapLatest { node ->
        val repository = node.repository
        combine(repository.lists(), selection) { lists, selected -> lists to (lists.firstOrNull { it.id == selected } ?: lists.firstOrNull()) }
            .flatMapLatest { (lists, list) ->
                if (list == null) {
                    flowOf(ListsState(lists, trusted = node.isTrusted, canCreateLists = node.canCreateLists))
                } else {
                    ListsState(lists, list, trusted = node.isTrusted, canCreateLists = node.canCreateLists).observeDetails(
                        repository.categories(list.id),
                        repository.observe(list.id),
                        repository.itemCategories(list.id),
                    )
                }
            }
    }.stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), ListsState(loading = true))

    val recipients: StateFlow<List<ShareRecipient>> = node.flatMapLatest { node ->
        if (node.isTrusted) {
            combine(node.household.devices(), node.household.registry()) { rows, devices ->
                registryRecipients(node.self, rows, devices)
            }
        } else {
            flow {
                while (true) {
                    emit(discoveredRecipients(node.self, node.rocky.network().peers))
                    delay(2_000)
                }
            }.settledOnRocky()
        }
    }.stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), emptyList())

    init {
        // A replica drops a whole transaction whose replay fails; its writes are gone, so say so.
        viewModelScope.launch {
            node.collectLatest { node ->
                // Ends when the database closes.
                node.rocky.drops().catch { }.collect { tell(dropMessage(it.outcome.reason)) }
            }
        }
    }

    fun shareWithDevice(recipient: String) = onList { household.share(it, recipient) }

    fun select(list: Long) {
        selection.value = list
        editor.category = null
    }

    /** New items go into the selected category. */
    fun selectCategory(category: Long?) {
        editor.category = state.value.categories.firstOrNull { it.id == category }
    }

    fun createList(title: String) = write { selection.value = repository.createList(title) }
    fun renameList(title: String) = onList { repository.renameList(it, title) }
    fun deleteList() = onList { repository.deleteList(it) }
    fun addCategory(name: String) = onList { list -> repository.addCategory(list, name).also { id -> if (state.value.selected?.id == list) editor.category = Category(list, id, name) } }
    fun deleteCategory(category: Long) = onList { repository.deleteCategory(it, category) }
    fun add() {
        val list = state.value.selected?.id ?: return
        val draft = editor.draft.text.toString()
        val title = draft.trim().takeIf { it.isNotEmpty() } ?: return
        if (editor.adding) return
        val category = state.value.categories.firstOrNull { it.id == editor.category?.id && it.list == editor.category?.list }?.id
        editor.adding = true
        write {
            try {
                repository.add(list, title, setOfNotNull(category))
                if (editor.draft.text.toString() == draft) editor.draft.clearText()
            } finally {
                editor.adding = false
            }
        }
    }
    fun toggle(item: ShoppingItem) = write { repository.check(item.list, item.id, !item.completed) }
    fun rename(item: ShoppingItem, title: String) = write { repository.rename(item.list, item.id, title) }
    fun categorize(item: ShoppingItem, category: Long, member: Boolean) = write { repository.categorize(item.list, item.id, category, member) }

    /** Moves the item [by] places in the whole list, whatever the filters show. */
    fun shift(item: ShoppingItem, by: Int) {
        val items = state.value.items
        val index = items.indexOfFirst { it.id == item.id }.takeIf { it >= 0 } ?: return
        val target = (index + by).coerceIn(0, items.lastIndex)
        if (target != index) write { repository.place(item.list, items, item.id, target) }
    }
    fun delete(item: ShoppingItem) = write { repository.delete(item.list, item.id) }
    fun move(item: ShoppingItem, to: Long) = write { repository.move(item.list, item.id, to) }

    private fun onList(action: suspend ShoppingNode.(Long) -> Unit) {
        val list = state.value.selected?.id ?: return
        write { action(list) }
    }
}

/** List tabs remain usable while one selected partition is recovering. */
internal fun ListsState.observeDetails(
    categories: Flow<List<Category>>,
    items: Flow<List<ShoppingItem>>,
    links: Flow<List<ItemCategory>>,
): Flow<ListsState> = combine(categories, items, links) { categories, items, links ->
    copy(categories = categories, items = items, links = links, contentLoading = false)
}.onStart { emit(copy(contentLoading = true)) }

/** The snackbar text for a dropped transaction, by its drop reason. */
internal fun dropMessage(reason: String): String = when (reason) {
    "constraint" -> "A change was undone: it clashed with another device's, such as a duplicate title"
    "admission" -> "A change was undone: its device may no longer write there"
    "schema" -> "A change was undone: a newer app version no longer accepts it"
    else -> "A change was undone on this device ($reason)"
}
